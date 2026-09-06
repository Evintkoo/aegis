//! discovery — actively map a target's attack surface before fuzzing.
//!
//! Port of `discovery.py`. Beyond parsing forms, this crawls same-origin
//! pages for links/forms with parameters, fetches robots.txt/sitemap.xml
//! for more URLs, mines same-origin JS bundles for API endpoints and
//! parameter names, and (Arjun-style) brute-forces a wordlist of common
//! parameter names against endpoints that expose none, keeping any name
//! that changes the response. Never crawls or fuzzes state-changing paths
//! (logout/delete/reset/...) and skips CSRF/CAPTCHA/token fields.
//!
//! Rust's `regex` crate has no lookaround support, unlike Python's `re`.
//! `JS_PATH_RE` below adapts around the one place the original relies on
//! a lookahead (see its doc comment) -- everything else ports directly.

use pentest_core::{HttpClient, HttpRequest};
use reqwest::Url;
use std::collections::{HashSet, VecDeque};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    Link,
    Form,
    Sitemap,
    Robots,
    Mined,
}

impl DiscoverySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Form => "form",
            Self::Sitemap => "sitemap",
            Self::Robots => "robots",
            Self::Mined => "mined",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredTarget {
    pub url: String,
    pub param: String,
    pub method: String,
    pub value: String,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MineMode {
    Auto,
    Aggressive,
    Off,
}

#[derive(Debug, Clone)]
pub struct DiscoveryOpts {
    pub crawl_pages: usize,
    pub max_targets: usize,
    pub mine: MineMode,
}

impl Default for DiscoveryOpts {
    fn default() -> Self {
        Self { crawl_pages: 10, max_targets: 25, mine: MineMode::Auto }
    }
}

const STATIC_EXT: &[&str] = &[
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
    ".mp4", ".webp", ".map",
];

const UNSAFE_MARKERS: &[&str] = &[
    "logout", "signout", "sign-out", "delete", "remove", "destroy", "drop", "deactivate", "cancel", "unsubscribe",
    "reset", "purge", "checkout", "pay",
];

const SKIP_FIELD_MARKERS: &[&str] = &["csrf", "token", "nonce", "authenticity", "captcha", "__viewstate"];

const COMMON_PARAMS: &[&str] = &[
    "id", "q", "s", "search", "query", "page", "p", "name", "user", "username", "email", "file", "path", "dir",
    "url", "uri", "redirect", "return", "next", "callback", "lang", "locale", "sort", "order", "filter", "category",
    "cat", "product", "item", "action", "view", "type", "key", "token", "ref", "code", "message", "comment",
    "title", "slug", "year", "month", "limit", "offset",
];
const CANARY: &str = "zqx9182probe";

static LINK_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)<a\b[^>]+href\s*=\s*["']([^"']+)["']"#).unwrap());
static SCRIPT_SRC_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)<script\b[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap());
static FORM_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?is)<form\b[^>]*>.*?</form>").unwrap());
static FORM_TAG_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)<form\b([^>]*)>").unwrap());
static ACTION_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap());
static METHOD_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?i)method\s*=\s*["']?\s*post"#).unwrap());
static INPUT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']"#).unwrap()
});
/// The original Python pattern uses a zero-width lookahead `(?=["'`?\s])`
/// to require (without consuming) a quote/backtick/`?`/whitespace right
/// after the matched path. Rust's `regex` crate has no lookaround, so this
/// version matches that trailing character as a normal (consumed,
/// uncaptured) part of the pattern instead. The only behavioral
/// difference: two matches sharing exactly one boundary character
/// back-to-back with no separator (e.g. literal `"/a"/b"` in the source)
/// would only find the first -- a pattern that doesn't occur in real
/// bundled/minified JS, which always separates adjacent string literals
/// with punctuation.
static JS_PATH_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"["'`](/[A-Za-z0-9_./-]{2,80})["'`?\s]"#).unwrap());
static JS_QUERY_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[?&]([A-Za-z0-9_-]{1,40})=").unwrap());
static LOC_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)<loc>\s*([^<\s]+)\s*</loc>").unwrap());
static ROBOTS_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?mi)^(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)").unwrap());

fn is_unsafe(text: &str) -> bool {
    let lower = text.to_lowercase();
    UNSAFE_MARKERS.iter().any(|m| lower.contains(m))
}

fn is_skip_field(name: &str) -> bool {
    let lower = name.to_lowercase();
    SKIP_FIELD_MARKERS.iter().any(|m| lower.contains(m))
}

fn is_page(url: &Url) -> bool {
    let path = url.path().to_lowercase();
    !STATIC_EXT.iter().any(|ext| path.ends_with(ext))
}

fn join(base: &Url, href: &str) -> Option<Url> {
    base.join(href).ok()
}

struct Discovery {
    targets: Vec<DiscoveredTarget>,
    keys: HashSet<(String, String, String)>,
    js_urls: HashSet<String>,
    endpoints: HashSet<String>,
    js_params: HashSet<String>,
}

impl Discovery {
    fn add_target(&mut self, url: &str, param: &str, method: &str, value: &str, source: DiscoverySource) {
        if is_skip_field(param) || is_unsafe(url) {
            return;
        }
        let key = (url.split('?').next().unwrap_or(url).to_string(), param.to_string(), method.to_string());
        if !self.keys.insert(key) {
            return;
        }
        self.targets.push(DiscoveredTarget {
            url: url.to_string(),
            param: param.to_string(),
            method: method.to_string(),
            value: if value.is_empty() { "1".to_string() } else { value.to_string() },
            source,
        });
    }

    fn note_url(&mut self, u: &Url, origin: &url::Origin, source: DiscoverySource) {
        if u.origin() != *origin || !is_page(u) || is_unsafe(u.as_str()) {
            return;
        }
        if u.query().is_some() {
            let pairs: Vec<(String, String)> = u.query_pairs().into_owned().collect();
            for (k, v) in pairs {
                self.add_target(u.as_str(), &k, "GET", &v, source);
            }
        } else {
            let mut e = u.clone();
            e.set_fragment(None);
            self.endpoints.insert(e.to_string());
        }
    }
}

async fn mine_params(client: &HttpClient, url: &str, names: &[String]) -> Vec<String> {
    let Ok(base) = client.request(HttpRequest::get().url(url)).await else {
        return Vec::new();
    };
    if base.status >= 400 {
        return Vec::new();
    }
    let mut found = Vec::new();
    for name in names {
        let Ok(r) = client.request(HttpRequest::get().url(url).param(name, CANARY)).await else {
            continue;
        };
        let reflected = r.body.contains(CANARY) && !base.body.contains(CANARY);
        let behavior_changed = r.status == base.status && (r.body.len() as i64 - base.body.len() as i64).unsigned_abs() > 60;
        if reflected || behavior_changed {
            found.push(name.clone());
        }
    }
    found
}

pub async fn discover(client: &HttpClient, base_url: &str, opts: &DiscoveryOpts) -> Vec<DiscoveredTarget> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };
    let origin = base.origin();
    let root = format!("{}://{}", base.scheme(), base.authority());
    let Ok(root_url) = Url::parse(&root) else {
        return Vec::new();
    };

    let mut d = Discovery {
        targets: Vec::new(),
        keys: HashSet::new(),
        js_urls: HashSet::new(),
        endpoints: HashSet::new(),
        js_params: HashSet::new(),
    };
    let mut seen_pages: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::from([base_url.to_string()]);

    // --- 1) crawl same-origin pages ---
    while let Some(page) = queue.pop_front() {
        if seen_pages.len() >= opts.crawl_pages || d.targets.len() >= opts.max_targets {
            break;
        }
        if !seen_pages.insert(page.clone()) {
            continue;
        }
        let Ok(page_url) = Url::parse(&page) else { continue };
        let Ok(r) = client.request(HttpRequest::get().url(&page)).await else {
            continue;
        };
        let ctype = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        if !ctype.contains("html") && page != base_url {
            continue;
        }

        for cap in SCRIPT_SRC_RE.captures_iter(&r.body) {
            if let Some(u) = join(&page_url, &cap[1]) {
                if u.origin() == origin && u.path().to_lowercase().ends_with(".js") {
                    d.js_urls.insert(u.to_string());
                }
            }
        }

        for cap in LINK_RE.captures_iter(&r.body) {
            let href = &cap[1];
            if href.starts_with("mailto:") || href.starts_with("tel:") || href.starts_with("javascript:") || href.starts_with('#') {
                continue;
            }
            let Some(u) = join(&page_url, href) else { continue };
            if u.origin() != origin || !is_page(&u) || is_unsafe(u.as_str()) {
                continue;
            }
            if u.query().is_some() {
                d.note_url(&u, &origin, DiscoverySource::Link);
            } else {
                let mut clean = u.clone();
                clean.set_fragment(None);
                let clean_s = clean.to_string();
                if !seen_pages.contains(&clean_s) && !queue.contains(&clean_s) && seen_pages.len() + queue.len() < opts.crawl_pages {
                    queue.push_back(clean_s.clone());
                    d.endpoints.insert(clean_s);
                }
            }
        }

        for form_match in FORM_RE.find_iter(&r.body) {
            let form = form_match.as_str().to_string();
            let attrs = FORM_TAG_RE.captures(&form).map(|c| c[1].to_string()).unwrap_or_default();
            let method = if METHOD_RE.is_match(&attrs) { "POST" } else { "GET" };
            let action_attr = ACTION_RE.captures(&attrs).map(|c| c[1].to_string());
            let action_url = match action_attr.as_deref() {
                Some("") | None => Some(page_url.clone()),
                Some(a) => join(&page_url, a),
            };
            let Some(action) = action_url else { continue };
            if action.origin() != origin || is_unsafe(action.as_str()) {
                continue;
            }
            for cap in INPUT_RE.captures_iter(&form) {
                d.add_target(action.as_str(), &cap[1], method, "test", DiscoverySource::Form);
            }
        }
    }

    // --- 2) robots.txt + sitemap.xml ---
    for path in ["/robots.txt", "/sitemap.xml"] {
        let Ok(rr) = client.request(HttpRequest::get().url(format!("{root}{path}"))).await else {
            continue;
        };
        if rr.status != 200 {
            continue;
        }
        if path.ends_with(".xml") {
            for cap in LOC_RE.captures_iter(&rr.body).take(100) {
                if let Ok(u) = Url::parse(cap[1].trim()) {
                    d.note_url(&u, &origin, DiscoverySource::Sitemap);
                }
            }
        } else {
            for cap in ROBOTS_RE.captures_iter(&rr.body) {
                if let Some(u) = join(&root_url, &cap[1]) {
                    d.note_url(&u, &origin, DiscoverySource::Robots);
                }
            }
        }
    }

    // --- 3) fetch JS bundles -> endpoints + param names ---
    let js_urls: Vec<String> = d.js_urls.iter().take(12).cloned().collect();
    for ju in js_urls {
        let Ok(jr) = client.request(HttpRequest::get().url(&ju)).await else {
            continue;
        };
        for cap in JS_PATH_RE.captures_iter(&jr.body) {
            if let Some(mut u) = join(&root_url, &cap[1]) {
                if is_page(&u) && !is_unsafe(u.as_str()) && u.origin() == origin {
                    u.set_query(None);
                    u.set_fragment(None);
                    d.endpoints.insert(u.to_string());
                }
            }
        }
        for cap in JS_QUERY_RE.captures_iter(&jr.body) {
            d.js_params.insert(cap[1].to_string());
        }
    }

    // --- 4) parameter mining on paramless endpoints ---
    if opts.mine != MineMode::Off {
        let mut wordlist: Vec<String> = Vec::new();
        let mut seen_words: HashSet<String> = HashSet::new();
        for w in d.js_params.iter().cloned().chain(COMMON_PARAMS.iter().map(|s| s.to_string())) {
            if wordlist.len() >= 45 {
                break;
            }
            if seen_words.insert(w.clone()) {
                wordlist.push(w);
            }
        }

        let cap = if opts.mine == MineMode::Aggressive { 12 } else { 4 };
        let mut to_mine: Vec<String> = vec![base_url.to_string()];
        let mut rest: Vec<String> = d.endpoints.iter().filter(|e| !e.contains('?')).cloned().collect();
        rest.sort();
        to_mine.extend(rest);

        let mut seen_mine: HashSet<String> = HashSet::new();
        let mut mined_count = 0;
        for url in &to_mine {
            if mined_count >= cap {
                break;
            }
            let key = url.split('?').next().unwrap_or(url).to_string();
            if !seen_mine.insert(key) {
                continue;
            }
            mined_count += 1;
            let found = mine_params(client, url, &wordlist).await;
            for name in found {
                d.add_target(url, &name, "GET", CANARY, DiscoverySource::Mined);
            }
        }
    }

    d.targets.truncate(opts.max_targets);
    d.targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::{HttpClient, HttpClientConfig};

    /// Discovery can fire dozens of requests in one run (parameter mining
    /// alone tries up to 45 names); the production default 400ms
    /// inter-request delay would make these tests take tens of seconds
    /// for no correctness benefit, so tests use a zero-delay client.
    fn fast_client(base_url: String) -> HttpClient {
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() };
        HttpClient::new(base_url, config)
    }

    #[tokio::test]
    async fn discover_finds_link_form_and_sitemap_params_same_origin_only() {
        let base = scripted_server(|req, self_url| match req.path.as_str() {
            "/" => ScriptedResponse::ok(
                r#"<html><body>
                    <a href="/item?id=1">item</a>
                    <a href="/style.css">style</a>
                    <a href="https://evil.example.com/x?y=1">offsite</a>
                    <form method="POST" action="/search"><input name="q"></form>
                    <script src="/app.js"></script>
                </body></html>"#,
            )
            .header("Content-Type", "text/html"),
            "/app.js" => ScriptedResponse::ok(r#"fetch("/api/widgets?limit=10")"#),
            "/robots.txt" => ScriptedResponse::ok("Disallow: /secret\n"),
            "/sitemap.xml" => {
                ScriptedResponse::ok(format!("<urlset><url><loc>{self_url}/products?cat=shoes</loc></url></urlset>"))
            }
            _ => ScriptedResponse::ok("ok"),
        })
        .await;
        let client = fast_client(format!("{base}/"));

        let opts = DiscoveryOpts { crawl_pages: 10, max_targets: 25, mine: MineMode::Off };
        let targets = discover(&client, &format!("{base}/"), &opts).await;

        let find = |param: &str, src: DiscoverySource| {
            targets.iter().find(|t| t.param == param && t.source == src)
        };

        let item = find("id", DiscoverySource::Link).expect("id param from link");
        assert!(item.url.ends_with("/item?id=1") || item.url.ends_with("/item"));
        assert_eq!(item.method, "GET");

        let search = find("q", DiscoverySource::Form).expect("q param from form");
        assert_eq!(search.method, "POST");
        assert!(search.url.ends_with("/search"));

        let cat = find("cat", DiscoverySource::Sitemap).expect("cat param from sitemap");
        assert_eq!(cat.method, "GET");
        assert!(cat.url.contains("/products"));

        assert!(!targets.iter().any(|t| t.param == "y"), "offsite link params must not appear");
    }

    #[tokio::test]
    async fn discover_skips_unsafe_paths_and_csrf_fields() {
        let base = scripted_server(|req, _self_url| match req.path.as_str() {
            "/" => ScriptedResponse::ok(
                r#"<html><body>
                    <a href="/logout?confirm=1">logout</a>
                    <form method="POST" action="/save">
                        <input name="csrf_token">
                        <input name="title">
                    </form>
                </body></html>"#,
            )
            .header("Content-Type", "text/html"),
            _ => ScriptedResponse::ok(""),
        })
        .await;
        let client = fast_client(format!("{base}/"));
        let opts = DiscoveryOpts { crawl_pages: 10, max_targets: 25, mine: MineMode::Off };
        let targets = discover(&client, &format!("{base}/"), &opts).await;

        assert!(!targets.iter().any(|t| t.param == "confirm"), "unsafe /logout path must be skipped");
        assert!(!targets.iter().any(|t| t.param == "csrf_token"), "csrf field must be skipped");
        assert!(targets.iter().any(|t| t.param == "title"), "non-csrf form field must still be discovered");
    }

    #[tokio::test]
    async fn discover_mines_hidden_params_when_endpoint_has_none() {
        let base = scripted_server(|req, _self_url| {
            if req.query.get("id").map(|v| v.as_str()) == Some("zqx9182probe") {
                return ScriptedResponse::ok("reflected:zqx9182probe");
            }
            match req.path.as_str() {
                "/" => ScriptedResponse::ok(r#"<html><body>no links here</body></html>"#)
                    .header("Content-Type", "text/html"),
                "/robots.txt" | "/sitemap.xml" => ScriptedResponse::ok(""),
                _ => ScriptedResponse::ok("base page, no reflection"),
            }
        })
        .await;
        let client = fast_client(format!("{base}/"));
        let opts = DiscoveryOpts { crawl_pages: 10, max_targets: 25, mine: MineMode::Auto };
        let targets = discover(&client, &format!("{base}/"), &opts).await;

        let mined = targets.iter().find(|t| t.param == "id" && t.source == DiscoverySource::Mined);
        assert!(mined.is_some(), "reflected canary on a paramless endpoint should be mined as 'id'");
    }
}

//! secrets_in_js — fetch served JS bundles and scan for leaked keys/secrets.
//! Port of `checks/secrets_in_js.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::collections::HashSet;
use std::sync::LazyLock;

pub const NAME: &str = "secrets_in_js";

static SCRIPT_SRC_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']?([^"'> ]+)"#).unwrap());

static SECRET_PATTERNS: LazyLock<Vec<(regex::Regex, Severity, &'static str)>> = LazyLock::new(
    || {
        vec![
        (regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), Severity::Critical, "AWS access key id"),
        (regex::Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(), Severity::High, "Google API key"),
        (regex::Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(), Severity::Critical, "Stripe live secret key"),
        (regex::Regex::new(r"xox[baprs]-[0-9A-Za-z\-]{10,}").unwrap(), Severity::Critical, "Slack token"),
        (regex::Regex::new(r"gh[pousr]_[A-Za-z0-9]{36}").unwrap(), Severity::Critical, "GitHub token"),
        (regex::Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(), Severity::Critical, "Private key"),
        (regex::Regex::new(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*").unwrap(), Severity::Medium, "JWT"),
        (
            regex::Regex::new(r#"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]"#).unwrap(),
            Severity::Medium,
            "hard-coded credential assignment",
        ),
        (regex::Regex::new(r"AIzaSy[A-Za-z0-9_\-]{33}").unwrap(), Severity::High, "Firebase/Google key"),
    ]
    },
);

fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.host_str() == b.host_str() && a.port() == b.port()
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(r) = client.request(HttpRequest::get()).await else {
        return out;
    };
    let base = client.base_url();
    let Ok(origin) = reqwest::Url::parse(base) else {
        return out;
    };

    let mut same_origin_urls = Vec::new();
    let mut seen_src = HashSet::new();
    for cap in SCRIPT_SRC_RE.captures_iter(&r.body) {
        let src = &cap[1];
        if let Ok(u) = origin.join(src) {
            if same_origin(&u, &origin) {
                let s = u.to_string();
                if seen_src.insert(s.clone()) {
                    same_origin_urls.push(s);
                }
            }
        }
    }

    let mut targets = vec![("inline HTML".to_string(), r.body.clone())];
    for u in same_origin_urls.into_iter().take(15) {
        if let Ok(jr) = client.request(HttpRequest::get().url(&u)).await {
            targets.push((u, jr.body));
        }
    }

    for (where_, text) in &targets {
        for (re, sev, label) in SECRET_PATTERNS.iter() {
            for m in re.find_iter(text) {
                let masked = format!("{}…", m.as_str().chars().take(12).collect::<String>());
                out.push(
                    Finding::new(
                        NAME,
                        *sev,
                        format!("{label} exposed in JS/HTML"),
                        format!("found in {where_}"),
                    )
                    .with_evidence(masked),
                );
            }
        }
    }

    // de-dup
    let mut keys = HashSet::new();
    let mut uniq = Vec::new();
    for f in out {
        let k = (f.title.clone(), f.evidence.clone());
        if keys.insert(k) {
            uniq.push(f);
        }
    }
    uniq
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::HttpClientConfig;

    fn fast_client(base_url: String) -> HttpClient {
        HttpClient::new(
            base_url,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                ..HttpClientConfig::default()
            },
        )
    }

    #[tokio::test]
    async fn detects_an_aws_key_leaked_in_inline_html() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok("<html><script>var k='AKIAABCDEFGHIJKLMNOP';</script></html>")
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "AWS access key id exposed in JS/HTML"
                && f.detail.contains("inline HTML")));
    }

    #[tokio::test]
    async fn fetches_a_same_origin_script_and_scans_it() {
        let base = scripted_server(|req, _| {
            if req.path == "/bundle.js" {
                ScriptedResponse::ok("const stripeKey = 'sk_live_abcdefghijklmnopqrstuvwx';")
            } else {
                ScriptedResponse::ok(r#"<html><script src="/bundle.js"></script></html>"#)
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "Stripe live secret key exposed in JS/HTML"
                && f.detail.contains("/bundle.js")));
    }

    #[tokio::test]
    async fn no_findings_on_a_clean_page() {
        let base =
            scripted_server(|_req, _| ScriptedResponse::ok("<html><body>hello</body></html>"))
                .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

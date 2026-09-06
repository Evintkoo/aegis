//! xss — reflected cross-site-scripting probe.
//!
//! Injects unique markers and checks whether they come back unencoded in
//! an HTML-dangerous context. Detection only -- never executes anything.
//! Port of `checks/xss.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "xss";

// Each marker is unique so we can confirm reflection unambiguously.
const PROBES: &[(&str, &str, &str)] = &[
    ("<zqx1>alert</zqx1>", "<zqx1>", "raw HTML tag reflected unencoded"),
    ("\"zqx2'>", "\"zqx2'>", "quote/angle-bracket breakout reflected unencoded"),
    ("javascript:zqx3", "javascript:zqx3", "reflected in a potential URL/js sink"),
];

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#x27;")
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(param) = &opts.param else {
        return out;
    };
    let method = opts.method.to_uppercase();
    let base = if opts.base_value.is_empty() { "test" } else { &opts.base_value };

    for (payload, needle, why) in PROBES {
        let val = format!("{base}{payload}");
        let req = if method == "POST" { HttpRequest::post().form_field(param, &val) } else { HttpRequest::get().param(param, &val) };
        let Ok(r) = client.request(req).await else { continue };
        let body = &r.body;

        // Reflected raw? (encoded reflection is safe and ignored). Mirrors
        // the Python original's check: the needle appears verbatim, and
        // the html-escaped form of the needle does not appear in the rest
        // of the body once one raw occurrence is excluded.
        if let Some(idx) = body.find(needle) {
            let escaped = html_escape(needle);
            let rest = format!("{}{}", &body[..idx], &body[idx + needle.len()..]);
            if !rest.contains(&escaped) {
                let ctype = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Content-Type")).map(|(_, v)| v.as_str()).unwrap_or("");
                if ctype.to_lowercase().contains("html") || ctype.is_empty() {
                    let snippet_start = idx.saturating_sub(40);
                    let snippet_end = (idx + needle.len() + 20).min(body.len());
                    let snippet = body[snippet_start..snippet_end].replace('\n', " ");
                    let mut f = Finding::new(NAME, Severity::High, "Reflected XSS", format!("{why} (param '{param}')")).with_evidence(snippet);
                    f.payload = val;
                    out.push(f);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::HttpClientConfig;

    fn fast_client(base_url: String) -> HttpClient {
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() };
        HttpClient::new(base_url, config)
    }

    #[tokio::test]
    async fn detects_unencoded_html_tag_reflection() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("<html><body>results for: {v}</body></html>")).header("Content-Type", "text/html")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("q".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Reflected XSS" && f.detail.contains("raw HTML tag")));
    }

    #[tokio::test]
    async fn ignores_html_escaped_reflection() {
        // The javascript:zqx3 probe has no HTML-special characters, so
        // entity-escaping can never visibly change it -- a real app
        // defends against that probe by rejecting/stripping the value
        // outright (a URL-scheme allow-list), not by HTML-escaping it.
        // Simulate exactly that split defense here.
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            if v.contains("zqx3") {
                ScriptedResponse::ok("<html><body>results for: (rejected)</body></html>").header("Content-Type", "text/html")
            } else {
                ScriptedResponse::ok(format!("<html><body>results for: {}</body></html>", html_escape(&v)))
                    .header("Content-Type", "text/html")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("q".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "HTML-escaped (or scheme-rejected) reflection must not be flagged");
    }

    #[tokio::test]
    async fn ignores_reflection_in_a_json_response() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("{{\"query\":\"{v}\"}}")).header("Content-Type", "application/json")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("q".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "non-HTML content types must not be flagged even if reflected raw");
    }

    #[tokio::test]
    async fn returns_empty_without_a_param() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let findings = run_impl(&client, &Opts::default()).await;
        assert!(findings.is_empty());
    }
}

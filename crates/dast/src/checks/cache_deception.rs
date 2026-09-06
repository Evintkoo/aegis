//! cache_deception — web cache deception on authenticated pages.
//!
//! If a private page is also served (identically) under a fake static
//! path like `/account/nonexistent.css` AND the response looks cacheable,
//! a CDN may cache the victim's private page at a URL the attacker can
//! then read. Most meaningful when an auth header/cookie is supplied
//! (`-H`). Port of `checks/cache_deception.py`.

use crate::checks::{path_root, similarity};
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::collections::HashMap;

pub const NAME: &str = "cache_deception";

const STATIC_TRICKS: &[&str] = &["/nonexistent.css", "%2fnonexistent.css", "/nonexistent.js", ";nonexistent.css", "/..%2fnonexistent.css"];

fn cacheable(headers: &HashMap<String, String>) -> bool {
    let cc = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Cache-Control")).map(|(_, v)| v.to_lowercase()).unwrap_or_default();
    if cc.contains("no-store") || cc.contains("private") {
        return false;
    }
    cc.contains("public") || cc.contains("max-age") || cc.is_empty() // absent CC often => CDN default caches
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let authed = client.header("Authorization").is_some() || client.header("Cookie").is_some();
    let base = path_root(client.base_url());

    let Ok(private) = client.request(HttpRequest::get()).await else { return out };
    if private.status >= 400 {
        return out;
    }

    // Calibration: if a definitely-missing static path ALSO returns the
    // private body, the server just echoes everything — inconclusive,
    // avoid false positive.
    let Ok(cal) = client.request(HttpRequest::get().url(format!("{base}/zzq_missing_9182.css")).no_redirects()).await else { return out };
    if cal.status == 200 && similarity(&cal.body, &private.body) > 0.9 {
        return out;
    }

    for trick in STATIC_TRICKS {
        let Ok(r) = client.request(HttpRequest::get().url(format!("{base}{trick}")).no_redirects()).await else { continue };
        // same private content served under a "static" URL?
        if r.status == 200 && similarity(&r.body, &private.body) > 0.9 && cacheable(&r.headers) {
            let sev = if authed { Severity::High } else { Severity::Medium };
            out.push(
                Finding::new(NAME, sev, "Web cache deception", format!("private page also served (cacheable) at '{trick}' — a CDN may cache and expose it"))
                    .with_evidence(format!("{base}{trick} -> HTTP 200, sim {:.2}", similarity(&r.body, &private.body))),
            );
            return out;
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
        HttpClient::new(base_url, HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() })
    }

    #[tokio::test]
    async fn detects_private_page_served_under_a_static_trick_path() {
        let base = scripted_server(|req, _| {
            if req.path == "/zzq_missing_9182.css" {
                ScriptedResponse::with_status(404, "not found")
            } else if req.path == "/nonexistent.css" {
                ScriptedResponse::ok("<html>my private account page</html>").header("Cache-Control", "public, max-age=600")
            } else {
                ScriptedResponse::ok("<html>my private account page</html>")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "Web cache deception"));
    }

    #[tokio::test]
    async fn no_finding_when_the_matched_path_is_not_cacheable() {
        let base = scripted_server(|req, _| {
            if req.path == "/nonexistent.css" {
                // The only trick path that echoes the private body -- and
                // it's explicitly marked non-cacheable. Every other path
                // (including the calibration probe) is a plain 404, so it
                // can never be mistaken for a second, unguarded match.
                ScriptedResponse::ok("<html>my private account page</html>").header("Cache-Control", "no-store")
            } else if req.path.is_empty() || req.path == "/" {
                ScriptedResponse::ok("<html>my private account page</html>")
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_the_server_echoes_everything_calibration_guard() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("<html>same body always</html>").header("Cache-Control", "public")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_the_base_page_itself_errors() {
        let base = scripted_server(|_req, _| ScriptedResponse::with_status(403, "forbidden")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

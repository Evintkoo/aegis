//! clickjacking — page framable due to missing XFO and CSP frame-ancestors.
//! Port of `checks/clickjacking.py`.
//!
//! Deviation: the Python original has a second `elif` branch meant to
//! report a "weak X-Frame-Options value" Low finding. Tracing its
//! condition (`xfo and not xfo_protected and not fa_protected`) against
//! the preceding `if` (`not xfo_protected and not fa_protected`) shows
//! it can never execute -- the `elif` only runs when the `if` was false,
//! which requires `xfo_protected or fa_protected`, directly contradicting
//! the `elif`'s own requirement that both be false. It's dead code in the
//! original, not a missed case; replicating unreachable code here would
//! itself violate this project's no-dead-code rule, so it's intentionally
//! not ported.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "clickjacking";

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(r) = client.request(HttpRequest::get()).await else { return out };

    let ctype = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Content-Type")).map(|(_, v)| v.as_str()).unwrap_or("");
    if !ctype.to_lowercase().contains("html") {
        return out; // only HTML pages are frameable in a meaningful way
    }

    let xfo = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("X-Frame-Options")).map(|(_, v)| v.to_uppercase()).unwrap_or_default();
    let csp = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Content-Security-Policy")).map(|(_, v)| v.clone()).unwrap_or_default();
    let fa_protected = csp.to_lowercase().contains("frame-ancestors");
    let xfo_protected = xfo == "DENY" || xfo == "SAMEORIGIN";

    if !xfo_protected && !fa_protected {
        out.push(
            Finding::new(
                NAME,
                Severity::Medium,
                "Page is framable (clickjacking)",
                "no X-Frame-Options and no CSP frame-ancestors — page can be embedded in an attacker iframe for UI-redress attacks",
            )
            .with_evidence(format!("XFO={}; frame-ancestors=absent", if xfo.is_empty() { "absent" } else { &xfo })),
        );
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
    async fn detects_a_framable_html_page() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("<html></html>").header("Content-Type", "text/html")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "Page is framable (clickjacking)"));
    }

    #[tokio::test]
    async fn no_finding_when_xfo_deny_is_set() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("<html></html>").header("Content-Type", "text/html").header("X-Frame-Options", "DENY")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_csp_frame_ancestors_is_set() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok("<html></html>").header("Content-Type", "text/html").header("Content-Security-Policy", "frame-ancestors 'self'")
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn ignores_non_html_responses() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("{}").header("Content-Type", "application/json")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

//! host_header — Host header injection (password-reset / cache poisoning
//! surface). Port of `checks/host_header.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "host_header";

const EVIL: &str = "evil.example.com";

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();

    // 1) Arbitrary Host accepted and reflected in body (absolute links / reset URLs)
    let Ok(r) = client
        .request(HttpRequest::get().header("Host", EVIL))
        .await
    else {
        return out;
    };
    if r.body.contains(EVIL) {
        out.push(
            Finding::new(
                NAME,
                Severity::High,
                "Host header reflected in response body",
                "arbitrary Host echoed — password-reset poisoning risk",
            )
            .with_evidence(format!("Host: {EVIL}")),
        );
    }

    // 2) X-Forwarded-Host override reflected (common framework trust)
    if let Ok(r2) = client
        .request(HttpRequest::get().header("X-Forwarded-Host", EVIL))
        .await
    {
        if r2.body.contains(EVIL) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::High,
                    "X-Forwarded-Host reflected in response",
                    "app trusts X-Forwarded-Host — reset/cache poisoning risk",
                )
                .with_evidence(format!("X-Forwarded-Host: {EVIL}")),
            );
        }
    }

    // 3) Host injection in redirect Location
    if let Ok(r3) = client
        .request(HttpRequest::get().header("Host", EVIL).no_redirects())
        .await
    {
        let loc = r3
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if loc.contains(EVIL) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::High,
                    "Host header controls redirect target",
                    "Location built from attacker Host",
                )
                .with_evidence(loc),
            );
        }
    }

    // 4) Does the server even validate Host? (200 to a bogus Host)
    if out.is_empty() && r.status < 400 {
        out.push(
            Finding::new(
                NAME,
                Severity::Low,
                "Server accepts arbitrary Host header",
                "no Host allow-listing (not reflected, but worth confirming vhosts)",
            )
            .with_evidence(format!("Host: {EVIL} -> HTTP {}", r.status)),
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
        HttpClient::new(
            base_url,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                ..HttpClientConfig::default()
            },
        )
    }

    #[tokio::test]
    async fn detects_host_reflected_in_body() {
        let base = scripted_server(|req, _| {
            let host = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            ScriptedResponse::ok(format!("<a href=\"http://{host}/reset\">reset</a>"))
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "Host header reflected in response body"));
    }

    #[tokio::test]
    async fn detects_x_forwarded_host_reflected() {
        let base = scripted_server(|req, _| {
            let xfh = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Forwarded-Host"))
                .map(|(_, v)| v.clone());
            match xfh {
                Some(h) => ScriptedResponse::ok(format!("base={h}")),
                None => ScriptedResponse::ok("no xfh header seen"),
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "X-Forwarded-Host reflected in response"));
    }

    #[tokio::test]
    async fn falls_back_to_low_severity_when_nothing_is_reflected() {
        let base =
            scripted_server(|_req, _| ScriptedResponse::ok("static page, ignores Host entirely"))
                .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "Server accepts arbitrary Host header"));
        assert_eq!(findings.len(), 1);
    }
}

//! crlf — CRLF injection / HTTP response splitting.
//!
//! Port of `checks/crlf.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "crlf";

const PAYLOADS: &[&str] = &[
    "%0d%0aX-Crlf-Test: injected",
    "%0d%0aSet-Cookie: crlftest=1",
    "%E5%98%8A%E5%98%8DX-Crlf-Test: injected", // unicode CR/LF trick
    "\r\nX-Crlf-Test: injected",
];

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(param) = &opts.param else {
        return out;
    };
    let method = opts.method.to_uppercase();
    let base = &opts.base_value;

    for p in PAYLOADS {
        let val = format!("{base}{p}");
        let req = if method == "POST" {
            HttpRequest::post().form_field(param, val).no_redirects()
        } else {
            HttpRequest::get().param(param, val).no_redirects()
        };
        let Ok(r) = client.request(req).await else { continue };

        if r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("X-Crlf-Test")) {
            out.push(Finding::new(NAME, Severity::High, "CRLF injection / response splitting", format!("payload injected a response header via '{param}'")).with_evidence(*p));
            break;
        }
        let set_cookie_has_marker = r
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("Set-Cookie") && v.to_lowercase().contains("crlftest"));
        if set_cookie_has_marker {
            out.push(Finding::new(NAME, Severity::High, "CRLF injection (Set-Cookie)", format!("payload injected a Set-Cookie via '{param}'")).with_evidence(*p));
            break;
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
    async fn detects_injected_response_header() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("next").cloned().unwrap_or_default();
            if v.to_lowercase().contains("crlf-test") {
                ScriptedResponse::ok("redirecting").header("X-Crlf-Test", "injected")
            } else {
                ScriptedResponse::ok("redirecting")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("next".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "CRLF injection / response splitting");
    }

    #[tokio::test]
    async fn detects_injected_set_cookie() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("next").cloned().unwrap_or_default();
            if v.to_lowercase().contains("set-cookie") {
                ScriptedResponse::ok("ok").header("Set-Cookie", "crlftest=1")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("next".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "CRLF injection (Set-Cookie)");
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let opts = Opts { param: Some("next".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn returns_empty_without_a_param() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let findings = run_impl(&client, &Opts::default()).await;
        assert!(findings.is_empty());
    }
}

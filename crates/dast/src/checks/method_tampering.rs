//! method_tampering — dangerous HTTP verbs, TRACE (XST), and override bypass.
//!
//! Non-destructive: PUT/DELETE are aimed at a unique random path (never a
//! real resource), and any file created by a successful PUT is
//! immediately DELETEd. Port of `checks/method_tampering.py`.

use crate::checks::path_root;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use reqwest::Method;

pub const NAME: &str = "method_tampering";

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = path_root(client.base_url());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let probe_path = format!("{root}/pentest_probe_{now}.txt");

    // 1) TRACE -> Cross-Site Tracing (echoes request, can leak headers/cookies)
    if let Ok(tr) = client
        .request(
            HttpRequest {
                method: Method::TRACE,
                ..HttpRequest::get()
            }
            .header("X-Xst-Probe", "trace-canary-9182"),
        )
        .await
    {
        if tr.body.contains("trace-canary-9182") && tr.status < 400 {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "HTTP TRACE enabled (XST)",
                    "server echoes the request — enables Cross-Site Tracing",
                )
                .with_evidence(
                    tr.body
                        .chars()
                        .take(80)
                        .collect::<String>()
                        .replace('\n', " "),
                ),
            );
        }
    }

    // 2) WebDAV PUT write (to a throwaway path), then clean up
    if let Ok(pr) = client
        .request(
            HttpRequest {
                method: Method::PUT,
                url: Some(probe_path.clone()),
                ..HttpRequest::get()
            }
            .raw_body(b"pentest-write-probe".to_vec()),
        )
        .await
    {
        if matches!(pr.status, 200 | 201 | 204) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::High,
                    "HTTP PUT allows file write (WebDAV)",
                    format!(
                        "PUT created {probe_path} (HTTP {}) — remote file upload",
                        pr.status
                    ),
                )
                .with_evidence(format!("HTTP {}", pr.status)),
            );
            if client
                .request(HttpRequest {
                    method: Method::DELETE,
                    url: Some(probe_path.clone()),
                    ..HttpRequest::get()
                })
                .await
                .is_err()
            {
                out.push(Finding::new(
                    NAME,
                    Severity::Info,
                    "Could not auto-delete PUT probe file",
                    format!("manually remove {probe_path}"),
                ));
            }
        }
    }

    // 3) Method-override header bypass (reach a method the WAF/route blocks)
    let override_result = client
        .request(
            HttpRequest::post()
                .header("X-HTTP-Method-Override", "PUT")
                .header("X-HTTP-Method", "PUT")
                .raw_body(b"probe".to_vec()),
        )
        .await;
    if let Ok(ov) = override_result {
        if let Ok(base_get) = client.request(HttpRequest::get()).await {
            if ov.status < 400 && ov.status != base_get.status && !matches!(ov.status, 405 | 501) {
                out.push(
                    Finding::new(NAME, Severity::Low, "Method-override header honored", "X-HTTP-Method-Override changed handling — may bypass method-based access controls")
                        .with_evidence(format!("POST+override -> HTTP {}", ov.status)),
                );
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
        HttpClient::new(
            base_url,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                ..HttpClientConfig::default()
            },
        )
    }

    #[tokio::test]
    async fn detects_trace_echoing_the_probe_header() {
        let base = scripted_server(|req, _| {
            if req.path == "/"
                && req
                    .headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("X-Xst-Probe") && v == "trace-canary-9182")
            {
                ScriptedResponse::ok("TRACE / HTTP/1.1\r\nX-Xst-Probe: trace-canary-9182\r\n")
            } else {
                ScriptedResponse::with_status(405, "method not allowed")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "HTTP TRACE enabled (XST)"));
    }

    #[tokio::test]
    async fn detects_put_write_and_cleans_up() {
        let base = scripted_server(|req, _| {
            if req.body == "pentest-write-probe" {
                ScriptedResponse::with_status(201, "created")
            } else if req.body.is_empty() {
                // The follow-up DELETE cleanup request.
                ScriptedResponse::with_status(204, "")
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "HTTP PUT allows file write (WebDAV)"));
        assert!(!findings
            .iter()
            .any(|f| f.title == "Could not auto-delete PUT probe file"));
    }

    #[tokio::test]
    async fn detects_method_override_bypass() {
        let base = scripted_server(|req, _| {
            let overridden = req
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("X-HTTP-Method-Override") && v == "PUT");
            if overridden {
                ScriptedResponse::ok("override honored")
            } else if req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("X-Xst-Probe"))
            {
                ScriptedResponse::with_status(405, "no trace")
            } else if req.path.contains("pentest_probe_") {
                ScriptedResponse::with_status(404, "no write")
            } else {
                ScriptedResponse::with_status(403, "baseline blocked")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "Method-override header honored"));
    }

    #[tokio::test]
    async fn no_findings_against_a_locked_down_server() {
        let base = scripted_server(|_req, _| ScriptedResponse::with_status(403, "forbidden")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

//! request_smuggling — bounded HTTP request-smuggling framing probe
//! (CL+TE conflict), opt-in via `--smuggling`.
//!
//! Detection technique (not exploitation): one POST carrying both
//! `Content-Length` and `Transfer-Encoding: chunked` is sent over a raw
//! socket — `reqwest` sanitizes conflicting framing headers, so the
//! probe can't go through the normal client. A spec-compliant stack
//! answers 400; a front-end/back-end pair that disagrees about framing
//! typically answers 200 (or otherwise mishandles the request), which
//! is the classic smuggling precondition. The body is an inert marker
//! that poisons nothing, the socket is closed immediately after reading
//! one response, and everything is bounded by a short timeout.
//!
//! Hard-bounded surface: exactly two probes (CL+TE, duplicate CL),
//! http:// targets only (the raw-socket path has no TLS), never runs
//! unless `--smuggling` is passed — a desync probe can confuse a
//! vulnerable front-end's connection reuse, so it is never default-on.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, Severity};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NAME: &str = "request_smuggling";

const TIMEOUT: Duration = Duration::from_secs(3);

/// Classifies a status code returned for a conflicting-framing probe.
/// 4xx (the RFC 9112-mandated 400 in particular) means the stack
/// rejected the request — safe. Anything else (2xx/5xx) means it was
/// processed despite the conflict. Exposed for testing.
pub fn classify_status(status: u16) -> &'static str {
    if (400..500).contains(&status) {
        "rejected"
    } else {
        "processed"
    }
}

fn host_port(base_url: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(base_url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    Some((host, port))
}

async fn raw_probe(addr: &str, request: &str) -> Option<(u16, String)> {
    let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let _ = stream.write_all(request.as_bytes()).await;
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let status = text.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, text.lines().next().unwrap_or("").to_string()))
}

/// Pure decision function over probe outcomes: (probe name, status).
/// Exposed for testing.
pub fn findings_from_probes(probes: &[(&str, u16)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (probe, status) in probes {
        if classify_status(*status) == "processed" {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "Conflicting HTTP framing accepted (request-smuggling precondition)",
                    format!("{probe} probe was processed (status {status}) instead of rejected with 400 — front/back-end framing disagreement is the precondition for smuggling"),
                )
                .with_evidence(format!("{probe} -> {status}")),
            );
        }
    }
    out
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    if !opts.smuggling {
        return Vec::new();
    }
    let Some((host, port)) = host_port(client.base_url()) else {
        return Vec::new();
    };
    let path = reqwest::Url::parse(client.base_url())
        .ok()
        .map(|u| u.path().to_string())
        .unwrap_or_else(|| "/".to_string());
    let addr = format!("{host}:{port}");
    let marker = "x=pentest-smuggle-probe";

    let cl_te = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n{marker}",
        marker.len()
    );
    let dup_cl = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n{marker}",
        len = marker.len()
    );

    let mut probes = Vec::new();
    for (name, request) in [("CL+TE", cl_te), ("dup-CL", dup_cl)] {
        if let Some((status, _)) = raw_probe(&addr, &request).await {
            probes.push((name, status));
        }
    }
    findings_from_probes(&probes)
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

    #[test]
    fn a_400_response_is_rejected_and_produces_no_finding() {
        assert_eq!(classify_status(400), "rejected");
        assert!(findings_from_probes(&[("CL+TE", 400), ("dup-CL", 400)]).is_empty());
    }

    #[test]
    fn a_200_or_500_response_is_processed_and_produces_a_finding() {
        assert_eq!(classify_status(200), "processed");
        let findings = findings_from_probes(&[("CL+TE", 200)]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[tokio::test]
    async fn flags_a_server_that_processes_conflicting_framing() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let opts = Opts {
            smuggling: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            !findings.is_empty(),
            "a 200-answering server must be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn does_not_flag_a_server_that_rejects_with_400() {
        let base = scripted_server(|req, _| {
            let has_cl = req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Content-Length"));
            let has_te = req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding"));
            let dup_cl = req
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
                .count()
                > 1;
            if (has_cl && has_te) || dup_cl {
                ScriptedResponse::with_status(400, "Bad Request")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            smuggling: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "a spec-compliant 400 answer must not be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn never_probes_without_the_opt_in_flag() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[test]
    fn host_port_only_accepts_plain_http_targets() {
        assert!(host_port("http://example.test:8080/x").is_some());
        assert!(host_port("https://example.test/x").is_none());
    }
}

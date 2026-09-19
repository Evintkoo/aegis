//! dom_xss — passive client-side (DOM) XSS sink analysis of served
//! JavaScript. No payloads are injected: the page and its same-origin
//! script bundles are fetched once and inspected for a DOM XSS *source*
//! (`location.hash`, `location.search`, `document.referrer`,
//! `document.URL`, `window.name`) flowing into a dangerous *sink*
//! (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
//! `eval`) within the same statement.
//!
//! Heuristic, deliberately conservative: a finding requires both a
//! source and a sink in the same statement (segment split on `;` and
//! newlines), so a bundle that merely mentions `location.hash` near an
//! unrelated `innerHTML` is not flagged.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::collections::HashSet;
use std::sync::LazyLock;

pub const NAME: &str = "dom_xss";

static SCRIPT_SRC_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']?([^"'> ]+)"#).unwrap());

const SOURCES: &[&str] = &[
    "location.hash",
    "location.search",
    "location.href",
    "document.referrer",
    "document.URL",
    "window.name",
];
const SINKS: &[&str] = &[
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "eval(",
];

/// Splits a script into approximate statements, then reports segments
/// that contain both a DOM XSS source and a sink. Exposed for testing.
pub fn flagged_segments(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in text.split([';', '\n']) {
        let has_source = SOURCES.iter().any(|s| seg.contains(s));
        let has_sink = SINKS.iter().any(|s| seg.contains(s));
        if has_source && has_sink {
            out.push(seg.trim().chars().take(120).collect::<String>());
        }
    }
    out
}

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

    let mut targets = vec![("inline HTML".to_string(), r.body.clone())];
    let mut seen = HashSet::new();
    for cap in SCRIPT_SRC_RE.captures_iter(&r.body) {
        if let Ok(u) = origin.join(&cap[1]) {
            if same_origin(&u, &origin) && seen.insert(u.to_string()) {
                if let Ok(jr) = client.request(HttpRequest::get().url(u.to_string())).await {
                    targets.push((u.to_string(), jr.body));
                }
            }
        }
    }

    let mut keys = HashSet::new();
    for (where_, text) in &targets {
        for seg in flagged_segments(text) {
            if keys.insert((where_.clone(), seg.clone())) {
                out.push(
                    Finding::new(
                        NAME,
                        Severity::Medium,
                        "Potential DOM XSS (source-to-sink in client JS)",
                        format!("found in {where_}"),
                    )
                    .with_evidence(seg),
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
    async fn detects_a_source_to_sink_flow_in_inline_script() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(
                r#"<html><script>el.innerHTML = location.hash.slice(1);</script></html>"#,
            )
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title.contains("DOM XSS") && f.evidence.contains("location.hash")));
    }

    #[tokio::test]
    async fn fetches_a_same_origin_bundle_and_flags_it() {
        let base = scripted_server(|req, _| {
            if req.path == "/app.js" {
                ScriptedResponse::ok(
                    "document.write('<b>' + decodeURIComponent(window.name) + '</b>');",
                )
            } else {
                ScriptedResponse::ok(r#"<html><script src="/app.js"></script></html>"#)
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.detail.contains("/app.js") && f.evidence.contains("window.name")));
    }

    #[tokio::test]
    async fn a_source_without_a_sink_in_the_same_statement_is_not_flagged() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(
                r#"<html><script>var h = location.hash; el.innerHTML = greeting;</script></html>"#,
            )
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(
            findings.is_empty(),
            "source and sink must co-occur in one statement, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn a_sink_assigned_a_literal_is_not_flagged() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(r#"<html><script>el.innerHTML = "<b>static</b>";</script></html>"#)
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

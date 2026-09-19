//! hpp — HTTP Parameter Pollution (WSTG 4.7.4, CWE-235).
//!
//! Sends the target parameter twice with different values (`base&param=2`
//! and `param=2&param=base`) and compares each against a single-value
//! baseline. A server with a defined, framework-consistent precedence
//! rule behaves as if only one value arrived — identical to the baseline
//! chosen accordingly. When the duplicate changes the response, the
//! application feeds both values into its logic differently (or relies
//! on an undefined precedence), which is the precondition for HPP
//! bypasses (filter evasion, double-vote, price-mix bugs).
//!
//! Tentative by design: divergence proves inconsistent duplicate handling,
//! not an exploitable flow. Bounded: baseline + 2 probes.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "hpp";

/// Relative body-length divergence tolerated before a response counts as
/// "different" (same threshold as `race_condition`/`business_logic`).
const LEN_TOLERANCE: f64 = 0.05;

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let Some(param) = &opts.param else {
        return Vec::new();
    };
    let method = opts.method.to_uppercase();
    let base = if opts.base_value.is_empty() {
        "1"
    } else {
        &opts.base_value
    };

    let baseline = if method == "POST" {
        client
            .request(HttpRequest::post().form_field(param, base))
            .await
    } else {
        client.request(HttpRequest::get().param(param, base)).await
    };
    let Ok(baseline) = baseline else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (first, second) in [
        (base.to_string(), "2".to_string()),
        ("2".to_string(), base.to_string()),
    ] {
        let req = if method == "POST" {
            // `form_field` is a map, so duplicates go via a literal
            // form-encoded body.
            HttpRequest::post()
                .raw_body(format!("{param}={first}&{param}={second}"))
                .header("Content-Type", "application/x-www-form-urlencoded")
        } else {
            HttpRequest::get().url(polluted_url(client.base_url(), param, &first, &second))
        };
        let Ok(r) = client.request(req).await else {
            continue;
        };
        if let Some(observed) = divergence(&baseline.status, &baseline.body, r.status, &r.body) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Low,
                    "Duplicate-parameter requests handled inconsistently",
                    format!(
                        "param '{param}' sent twice ({first} then {second}) produced a different response than the single-value baseline — server-side duplicate handling is undefined or split across components (tentative)"
                    ),
                )
                .with_evidence(observed),
            );
        }
    }
    out
}

/// Builds the base URL with `param` appearing twice, preserving any
/// existing query string.
fn polluted_url(base_url: &str, param: &str, first: &str, second: &str) -> String {
    let p = urlencode(param);
    let (root, sep) = if base_url.contains('?') {
        (base_url.to_string(), "&")
    } else {
        (base_url.to_string(), "?")
    };
    format!("{root}{sep}{p}={first}&{p}={second}")
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Pure decision function, exposed for testing (same contract as
/// `business_logic::divergence`).
pub fn divergence(
    baseline_status: &u16,
    baseline_body: &str,
    probe_status: u16,
    probe_body: &str,
) -> Option<String> {
    if probe_status != *baseline_status {
        return Some(format!("status {baseline_status} -> {probe_status}"));
    }
    let base_len = baseline_body.len().max(1) as f64;
    let drift = (probe_body.len() as f64 - base_len).abs() / base_len;
    if drift > LEN_TOLERANCE {
        return Some(format!(
            "body length {} -> {}",
            baseline_body.len(),
            probe_body.len()
        ));
    }
    None
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
    async fn flags_a_server_that_takes_the_last_duplicate() {
        // Last-wins parsing: baseline id=1 resolves the item; the
        // duplicate probe (1, 2) resolves id=2, which 404s — a status
        // divergence purely from duplicate handling.
        let base = scripted_server(|req, _| {
            let v = req.query.get("id").cloned().unwrap_or_default();
            if v == "1" {
                ScriptedResponse::ok("item 1")
            } else {
                ScriptedResponse::with_status(404, "no such item")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.iter().any(|f| f.evidence.starts_with("status")),
            "last-wins duplicate handling must be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn only_the_reversed_order_probe_diverges_when_baseline_order_wins() {
        // With last-wins parsing, the (1, 2) probe diverges (resolves 2)
        // while the (2, 1) probe re-resolves 1 — identical to baseline —
        // so exactly one finding is produced. This documents that both
        // orderings are probed before concluding consistency.
        let base = scripted_server(|req, _| {
            let v = req.query.get("id").cloned().unwrap_or_default();
            if v == "1" {
                ScriptedResponse::ok("item 1 body")
            } else {
                ScriptedResponse::ok("an entirely different shaped response body for item 2")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1, "got {findings:?}");
    }

    #[tokio::test]
    async fn fully_consistent_server_produces_no_findings() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("stable body")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn polluted_url_preserves_existing_query() {
        assert_eq!(
            polluted_url("http://x.test/item?id=1", "id", "1", "2"),
            "http://x.test/item?id=1&id=1&id=2"
        );
        assert_eq!(
            polluted_url("http://x.test/item", "id", "1", "2"),
            "http://x.test/item?id=1&id=2"
        );
        assert_eq!(
            polluted_url("http://x.test/item", "a b", "1", "2"),
            "http://x.test/item?a%20b=1&a%20b=2"
        );
    }

    #[test]
    fn divergence_decision_matches_status_then_length() {
        assert!(divergence(&200, "ok", 200, "ok").is_none());
        assert_eq!(
            divergence(&200, "ok", 500, "ok").as_deref(),
            Some("status 200 -> 500")
        );
        assert_eq!(
            divergence(&200, "ok", 200, "ok but much longer response now").as_deref(),
            Some("body length 2 -> 31")
        );
        assert!(divergence(&200, "ok", 200, "ox").is_none());
    }
}

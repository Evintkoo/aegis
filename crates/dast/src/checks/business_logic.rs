//! business_logic — out-of-domain value probe (CWE-20, business-logic
//! layer), opt-in via `--logic`.
//!
//! Sends a small, bounded set of *out-of-domain* values for the target
//! parameter — negative, zero, non-integer float, and positive/negative
//! integer overflow — and compares each response against a baseline
//! request carrying the parameter's original value. An endpoint that
//! handles `-1`, `0`, or `99999999999999999999` exactly like `1` has
//! domain validation; one that errors out, changes status, or returns
//! differently-shaped content is trusting the client to send in-domain
//! data — the precondition for negative-quantity refunds, zero-price
//! checkouts, and ID-shift bugs.
//!
//! These values can be state-changing on a POST endpoint (a `-1` amount
//! could be *processed*), so the check is never default-on and assumes a
//! staging target. Tentative by design: divergence shows missing input
//! validation, not a proven exploit — each hit needs manual
//! interpretation against the business rule the parameter feeds.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "business_logic";

const PROBES: &[(&str, &str)] = &[
    ("-1", "negative"),
    ("0", "zero"),
    ("1.5", "non-integer float"),
    ("99999999999999999999", "integer overflow (positive)"),
    ("-99999999999999999999", "integer overflow (negative)"),
];

/// Relative body-length divergence tolerated before a probe response
/// counts as "different" from the baseline (absorbs dynamic nonce/banner
/// noise in otherwise-identical pages). Same threshold as
/// `race_condition` for consistency across the behavioral checks.
const LEN_TOLERANCE: f64 = 0.05;

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    if !opts.logic {
        return Vec::new();
    }
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
    for &(payload, label) in PROBES {
        let req = if method == "POST" {
            HttpRequest::post().form_field(param, payload)
        } else {
            HttpRequest::get().param(param, payload)
        };
        let Ok(r) = client.request(req).await else {
            continue;
        };
        if let Some(observed) = divergence(&baseline.status, &baseline.body, r.status, &r.body) {
            let mut f = Finding::new(
                NAME,
                Severity::Low,
                "Out-of-domain value handled differently",
                format!(
                    "param '{param}' accepted {label} value '{payload}' and behaved differently (tentative — interpret against the business rule this parameter feeds)"
                ),
            )
            .with_evidence(observed);
            f.payload = payload.to_string();
            out.push(f);
        }
    }
    out
}

/// Pure decision function, exposed for testing: how the probe response
/// diverged from the baseline (status change or body-length drift beyond
/// tolerance), or `None` when the endpoint handled the value in-domain.
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
    async fn flags_a_zero_value_that_hard_errors() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("amount").cloned().unwrap_or_default();
            if v == "0" {
                ScriptedResponse::with_status(500, "TypeError: amount must be > 0")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("amount".to_string()),
            logic: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings
                .iter()
                .any(|f| f.evidence.contains("status 200 -> 500")),
            "a zero-value hard error must be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn flags_an_overflow_value_that_changes_the_body_shape() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("id").cloned().unwrap_or_default();
            if v.len() > 10 {
                ScriptedResponse::ok(format!("dumped {v} with a very long debug trace explaining the overflow condition in detail"))
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            logic: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings
                .iter()
                .any(|f| f.evidence.starts_with("body length")),
            "an overflow-induced body-shape change must be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn quiet_when_every_value_is_handled_identically() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            logic: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[tokio::test]
    async fn never_probes_without_the_opt_in_flag() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn needs_a_param_even_when_opted_in() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let opts = Opts {
            logic: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
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
        // 3 vs 2 chars is 50% drift — well beyond the 5% tolerance
        assert_eq!(
            divergence(&200, "ok", 200, "ok.").as_deref(),
            Some("body length 2 -> 3")
        );
        // same length (2 chars) as the baseline — within tolerance
        assert!(divergence(&200, "ok", 200, "ox").is_none());
    }
}

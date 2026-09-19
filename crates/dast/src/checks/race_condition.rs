//! race_condition — concurrent duplicate-request consistency probe,
//! opt-in via `--race`.
//!
//! Sends a small burst (8) of *identical* concurrent GETs alongside a
//! sequential baseline. Read-only endpoints with correct locking,
//! idempotent caching, or transactional reads answer every duplicate
//! identically; responses that diverge mid-burst (different status, or
//! body length differing by more than a tolerance) indicate the kind of
//! missing lock / read-during-write inconsistency that becomes a
//! race condition once the endpoint mutates state. Tentative by
//! design: divergence is evidence of inconsistency, not proof of
//! exploitability.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "race_condition";

const BURST: usize = 8;
/// Relative body-length divergence tolerated before responses count as
/// "different" (absorbs dynamic nonce/banner noise in otherwise-identical
/// pages).
const LEN_TOLERANCE: f64 = 0.05;

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    if !opts.race {
        return Vec::new();
    }
    let Ok(baseline) = client.request(HttpRequest::get()).await else {
        return Vec::new();
    };

    // Urgent: the rate limiter would serialize the join! into
    // ~delay-spaced probes, hiding exactly the divergence hunted here.
    let f1 = client.request(HttpRequest::get().urgent());
    let f2 = client.request(HttpRequest::get().urgent());
    let f3 = client.request(HttpRequest::get().urgent());
    let f4 = client.request(HttpRequest::get().urgent());
    let f5 = client.request(HttpRequest::get().urgent());
    let f6 = client.request(HttpRequest::get().urgent());
    let f7 = client.request(HttpRequest::get().urgent());
    let f8 = client.request(HttpRequest::get().urgent());
    let (r1, r2, r3, r4, r5, r6, r7, r8) = tokio::join!(f1, f2, f3, f4, f5, f6, f7, f8);
    let burst: Vec<_> = [r1, r2, r3, r4, r5, r6, r7, r8]
        .into_iter()
        .flatten()
        .collect();
    if burst.len() < BURST {
        return Vec::new();
    }

    let mut statuses: Vec<u16> = burst.iter().map(|r| r.status).collect();
    statuses.push(baseline.status);
    statuses.sort_unstable();
    statuses.dedup();

    let base_len = baseline.body.len().max(1);
    let divergent_len = burst.iter().any(|r| {
        let d = (r.body.len() as f64 - baseline.body.len() as f64).abs() / base_len as f64;
        d > LEN_TOLERANCE
    });

    findings_from_observations(&statuses, divergent_len)
}

/// Pure decision function, exposed for testing: more than one distinct
/// status, or a burst response whose length diverges beyond tolerance
/// from the baseline, is reported as a tentative consistency finding.
pub fn findings_from_observations(statuses: &[u16], divergent_len: bool) -> Vec<Finding> {
    let distinct_status = statuses
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        > 1;
    if !distinct_status && !divergent_len {
        return Vec::new();
    }
    let why = if distinct_status && divergent_len {
        "differing status codes AND body shapes"
    } else if distinct_status {
        "differing status codes"
    } else {
        "differing body shapes"
    };
    vec![Finding::new(
        NAME,
        Severity::Low,
        "Inconsistent responses under concurrent duplicate requests",
        format!("{BURST} identical concurrent requests disagreed ({why}) — indicates missing locking; tentative, verify manually"),
    )
    .with_evidence(format!("statuses={:?}", statuses))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::HttpClientConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
    async fn flags_a_server_whose_responses_diverge_mid_burst() {
        let counter = Arc::new(AtomicUsize::new(0));
        let base = scripted_server(move |_req, _| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n.is_multiple_of(3) {
                ScriptedResponse::ok("<html><body>version A of the page</body></html>")
            } else {
                ScriptedResponse::ok("<html><body>version B</body></html>")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            race: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Inconsistent responses")),
            "got {findings:?}"
        );
    }

    #[tokio::test]
    async fn does_not_flag_a_stable_server() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok("<html><body>stable page</body></html>")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            race: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[tokio::test]
    async fn never_probes_without_the_opt_in_flag() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[test]
    fn findings_from_observations_decides_correctly() {
        assert!(findings_from_observations(&[200, 200, 200], false).is_empty());
        assert!(!findings_from_observations(&[200, 500, 200], false).is_empty());
        assert!(!findings_from_observations(&[200, 200], true).is_empty());
    }
}

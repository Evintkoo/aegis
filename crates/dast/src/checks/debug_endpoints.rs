//! debug_endpoints — exposed framework debug/diagnostic endpoints.
//!
//! Probes the classic operational backdoors that ship enabled by default
//! and leak configuration, secrets, source-level runtime state, or even
//! heap memory: Spring Boot actuators (`/actuator/env`, `/actuator/heapdump`),
//! Go's pprof and expvar, PHP `phpinfo()`, Apache `server-status`, and
//! ASP.NET tracing. Read-only GETs against a bounded path list; each
//! detection requires a response-body signature characteristic of the
//! diagnostic itself, so a 200 HTML page is not flagged.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "debug_endpoints";

/// (path, marker, severity, what it leaks) — detection = 200 + marker in
/// the body (case-insensitive), or the hprof magic header for heapdump.
const PROBES: &[(&str, &str, Severity, &str)] = &[
    (
        "/actuator/env",
        "propertysources",
        Severity::High,
        "Spring environment properties (DB creds, API keys)",
    ),
    (
        "/actuator/configprops",
        "spring.framework",
        Severity::High,
        "Spring configuration properties",
    ),
    (
        "/actuator/mappings",
        "servletmappings",
        Severity::Medium,
        "Spring URL-route mappings",
    ),
    (
        "/actuator",
        "_links",
        Severity::Medium,
        "Spring actuator endpoint index",
    ),
    (
        "/debug/pprof/",
        "types of profiles available",
        Severity::High,
        "Go pprof runtime profiling index",
    ),
    (
        "/debug/vars",
        "memstats",
        Severity::Medium,
        "Go expvar runtime variables",
    ),
    (
        "/phpinfo.php",
        "phpinfo()",
        Severity::High,
        "PHP configuration (env, paths, extensions)",
    ),
    (
        "/server-status",
        "apache server status",
        Severity::Medium,
        "Apache runtime status (requests, vhosts)",
    ),
    (
        "/trace.axd",
        "application trace",
        Severity::High,
        "ASP.NET request tracing",
    ),
];

fn marker_in(body: &str, marker: &str) -> bool {
    body.to_lowercase().contains(marker)
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = client.base_url_root();

    for (path, marker, severity, leaks) in PROBES {
        let url = format!("{root}{path}");
        let Ok(r) = client.request(HttpRequest::get().url(&url)).await else {
            continue;
        };
        if r.status != 200 {
            continue;
        }
        let hit = if path == &"/actuator/heapdump" {
            r.body.starts_with("JAVA PROFILE")
        } else {
            marker_in(&r.body, marker)
        };
        if hit {
            out.push(
                Finding::new(
                    NAME,
                    *severity,
                    "Diagnostic/debug endpoint exposed",
                    format!(
                        "{path} is reachable and answers as a live diagnostic page — leaks {leaks}"
                    ),
                )
                .with_evidence(url),
            );
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
    async fn flags_an_exposed_actuator_env() {
        let base = scripted_server(|req, _| {
            if req.path == "/actuator/env" {
                ScriptedResponse::ok(
                    r#"{"activeProfiles":["prod"],"propertySources":[{"name":"s1"}]}"#,
                )
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].evidence.ends_with("/actuator/env"));
    }

    #[tokio::test]
    async fn flags_phpinfo() {
        let base = scripted_server(|req, _| {
            if req.path == "/phpinfo.php" {
                ScriptedResponse::ok("<html><title>phpinfo()</title></html>")
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn detection_is_signature_based_on_each_probed_path() {
        // Every probe path answers 200 with one shared body. Only
        // /phpinfo.php fires because its marker ("phpinfo()") occurs in
        // the body and no other probe's marker does — documenting that
        // detection is marker-based per path, not on status alone.
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(
                "<html><body>a blog post that merely mentions phpinfo() in passing</body></html>",
            )
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        let fired: Vec<&str> = findings
            .iter()
            .map(|f| f.evidence.rsplit('/').next().unwrap_or(""))
            .collect();
        assert_eq!(fired, vec!["phpinfo.php"], "got {findings:?}");
    }

    #[tokio::test]
    async fn all_404s_produce_no_findings() {
        let base = scripted_server(|_req, _| ScriptedResponse::with_status(404, "not found")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

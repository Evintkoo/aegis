//! ldap_injection — LDAP filter injection (auth-bypass & error based).
//!
//! Port of `checks/ldap_injection.py`.

use crate::checks::similarity;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "ldap_injection";

static ERROR_MARKERS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)javax\.naming|com\.sun\.jndi|LDAPException|Bad search filter|Invalid DN syntax|Protocol error|ldap_search|Invalid credentials").unwrap()
});

// Wildcard/breakout payloads; `*` should widen results if injected into a filter.
const PAYLOADS: &[&str] = &[
    "*",
    "*)(uid=*))(|(uid=*",
    "*)(|(objectclass=*",
    "admin)(&))",
    ")(cn=*",
    "*))%00",
    "*()|&'",
];

async fn send(
    client: &HttpClient,
    method: &str,
    param: &str,
    val: &str,
) -> Option<pentest_core::HttpResponse> {
    let req = if method == "POST" {
        HttpRequest::post().form_field(param, val)
    } else {
        HttpRequest::get().param(param, val)
    };
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
    let base = if opts.base_value.is_empty() {
        "test"
    } else {
        &opts.base_value
    };

    let Some(baseline) = send(client, &method, param, base).await else {
        return out;
    };

    for p in PAYLOADS {
        let Some(r) = send(client, &method, param, p).await else {
            continue;
        };
        if let Some(m) = ERROR_MARKERS.find(&r.body) {
            if ERROR_MARKERS.find(&baseline.body).is_none() {
                out.push(
                    Finding::new(
                        NAME,
                        Severity::High,
                        "LDAP injection (error-based)",
                        format!("payload {p:?} triggered an LDAP error"),
                    )
                    .with_evidence(m.as_str()),
                );
                return out;
            }
        }
        // `*` widening: response grows substantially / diverges but stays 2xx
        if *p == "*"
            && r.status < 400
            && similarity(&r.body, &baseline.body) < 0.85
            && r.body.len() > (baseline.body.len() as f64 * 1.2) as usize
        {
            out.push(
                Finding::new(
                    NAME,
                    Severity::High,
                    "Possible LDAP injection (wildcard widened results)",
                    "'*' returned a larger/different result set",
                )
                .with_evidence(format!(
                    "len {}->{}",
                    baseline.body.len(),
                    r.body.len()
                )),
            );
            return out;
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
        let config = HttpClientConfig {
            delay: std::time::Duration::from_millis(0),
            ..HttpClientConfig::default()
        };
        HttpClient::new(base_url, config)
    }

    #[tokio::test]
    async fn detects_error_based_injection() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("uid").cloned().unwrap_or_default();
            if v.contains(')') {
                ScriptedResponse::ok("javax.naming.NamingException: Bad search filter")
            } else {
                ScriptedResponse::ok("no results")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("uid".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "LDAP injection (error-based)");
    }

    #[tokio::test]
    async fn detects_wildcard_widened_results() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("uid").cloned().unwrap_or_default();
            if v == "*" {
                ScriptedResponse::ok("<ul>".to_string() + &"<li>user</li>".repeat(50) + "</ul>")
            } else {
                ScriptedResponse::ok("<ul></ul>")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("uid".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].title,
            "Possible LDAP injection (wildcard widened results)"
        );
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("no results")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("uid".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn returns_empty_without_a_param() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let findings = run_impl(&client, &Opts::default()).await;
        assert!(findings.is_empty());
    }
}

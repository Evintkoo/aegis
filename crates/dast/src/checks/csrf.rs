//! csrf — detect state-changing forms lacking anti-CSRF tokens.
//! Port of `checks/csrf.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "csrf";

static FORM_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?is)(<form\b[^>]*>.*?</form>)").unwrap());
static METHOD_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?i)method\s*=\s*["']?\s*post"#).unwrap());
static ACTION_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap());
static TOKEN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)name\s*=\s*["']([^"']*(csrf|token|nonce|authenticity|_token|xsrf)[^"']*)["']"#).unwrap());

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(r) = client.request(HttpRequest::get()).await else { return out };

    for cap in FORM_RE.captures_iter(&r.body) {
        let form_body = &cap[1];
        let is_post = METHOD_RE.is_match(form_body);
        let has_token = TOKEN_RE.is_match(form_body);
        let action_s = ACTION_RE.captures(form_body).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()).unwrap_or_else(|| "(same URL)".to_string());
        if is_post && !has_token {
            out.push(
                Finding::new(NAME, Severity::Medium, "POST form without anti-CSRF token", format!("form action={action_s} has no hidden CSRF token field"))
                    .with_evidence(form_body.chars().take(100).collect::<String>().replace('\n', " ")),
            );
        }
    }

    // Cookie SameSite as a secondary CSRF control
    for (k, v) in &r.headers {
        if k.eq_ignore_ascii_case("set-cookie") && !v.to_lowercase().contains("samesite") {
            let cookie = v.split('=').next().unwrap_or(v);
            out.push(
                Finding::new(NAME, Severity::Low, format!("Cookie '{cookie}' lacks SameSite"), "SameSite absent weakens CSRF defense-in-depth")
                    .with_evidence(v.chars().take(80).collect::<String>()),
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
        HttpClient::new(base_url, HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() })
    }

    #[tokio::test]
    async fn detects_post_form_without_csrf_token() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(r#"<html><body><form method="POST" action="/transfer"><input name="amount"></form></body></html>"#)
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "POST form without anti-CSRF token" && f.detail.contains("/transfer")));
    }

    #[tokio::test]
    async fn does_not_flag_a_post_form_with_a_csrf_token() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(r#"<form method="POST" action="/transfer"><input type="hidden" name="csrf_token" value="abc"></form>"#)
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn flags_a_cookie_missing_samesite() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("<html></html>").header("Set-Cookie", "session=abc; HttpOnly")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title.contains("lacks SameSite")));
    }
}

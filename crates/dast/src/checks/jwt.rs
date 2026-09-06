//! jwt — static analysis of any JWT found in request headers/cookies.
//!
//! Detection-only: it inspects a token you already hold (via `-H`) and
//! reports weak algorithms, missing expiry, and sensitive claims. It does
//! NOT forge tokens. Port of `checks/jwt.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use base64::Engine;
use pentest_core::{Finding, HttpClient, Severity};
use std::collections::HashMap;
use std::sync::LazyLock;

pub const NAME: &str = "jwt";

static JWT_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").unwrap());

const SENSITIVE_KEYS: &[&str] = &["password", "pwd", "secret", "ssn", "credit_card", "role", "is_admin", "admin"];

fn b64_decode(seg: &str) -> Option<Vec<u8>> {
    let mut s = seg.to_string();
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    base64::engine::general_purpose::URL_SAFE.decode(s).ok()
}

fn find_tokens(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut tokens = Vec::new();
    for (k, v) in headers {
        for m in JWT_RE.find_iter(v) {
            tokens.push((k.clone(), m.as_str().to_string()));
        }
    }
    tokens
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let tokens = find_tokens(client.headers());
    if tokens.is_empty() {
        return vec![Finding::new(NAME, Severity::Info, "JWT check skipped", "no JWT found in supplied headers (pass one via -H 'Authorization: Bearer ...')")];
    }

    for (src, tok) in tokens {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 3 {
            continue;
        }
        let (Some(header_bytes), Some(payload_bytes)) = (b64_decode(parts[0]), b64_decode(parts[1])) else { continue };
        let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else { continue };
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else { continue };

        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        if alg == "none" {
            out.push(Finding::new(NAME, Severity::Critical, "JWT alg=none", "token accepts unsigned 'none' algorithm").with_evidence(format!("header={header}")));
        } else if alg.starts_with("hs") {
            out.push(
                Finding::new(NAME, Severity::Medium, "JWT uses symmetric HMAC (HS*)", "verify the signing secret is strong & not guessable; watch for RS256->HS256 confusion")
                    .with_evidence(format!("alg={}", header.get("alg").and_then(|v| v.as_str()).unwrap_or(""))),
            );
        }

        match payload.get("exp") {
            None => {
                out.push(Finding::new(NAME, Severity::Medium, "JWT has no expiry (exp)", "token never expires — stolen tokens valid forever").with_evidence(format!("src={src}")));
            }
            Some(exp_val) => {
                if let Some(exp) = exp_val.as_f64() {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
                    if exp < now {
                        out.push(Finding::new(NAME, Severity::Low, "JWT already expired", "supplied token is past exp").with_evidence(format!("exp={exp_val}")));
                    }
                }
            }
        }

        let sensitive: Vec<String> = payload
            .as_object()
            .map(|obj| obj.keys().filter(|k| SENSITIVE_KEYS.contains(&k.to_lowercase().as_str())).cloned().collect())
            .unwrap_or_default();
        if !sensitive.is_empty() {
            out.push(
                Finding::new(NAME, Severity::Low, "JWT carries sensitive/authz claims in payload", format!("claims are base64 (not encrypted): {sensitive:?}"))
                    .with_evidence(format!("{sensitive:?}")),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::scripted_server;
    use pentest_core::HttpClientConfig;

    fn client_with_auth(base_url: String, bearer: &str) -> HttpClient {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {bearer}"));
        HttpClient::new(base_url, HttpClientConfig { delay: std::time::Duration::from_millis(0), headers, ..HttpClientConfig::default() })
    }

    fn make_jwt(header_json: &str, payload_json: &str) -> String {
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{}.{}.sig", enc.encode(header_json), enc.encode(payload_json))
    }

    #[tokio::test]
    async fn returns_a_skip_notice_when_no_jwt_is_supplied() {
        let base = scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok")).await;
        let client = HttpClient::new(base, HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() });

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "JWT check skipped");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn detects_alg_none_and_missing_expiry() {
        let base = scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok")).await;
        let tok = make_jwt(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"u1"}"#);
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "JWT alg=none"));
        assert!(findings.iter().any(|f| f.title == "JWT has no expiry (exp)"));
    }

    #[tokio::test]
    async fn detects_expired_token_and_sensitive_claims() {
        let base = scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok")).await;
        let tok = make_jwt(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"exp":1,"is_admin":true}"#);
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "JWT uses symmetric HMAC (HS*)"));
        assert!(findings.iter().any(|f| f.title == "JWT already expired"));
        assert!(findings.iter().any(|f| f.title.contains("sensitive/authz claims")));
    }

    #[tokio::test]
    async fn no_findings_for_a_well_formed_unexpired_token() {
        let base = scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok")).await;
        let far_future = 9_999_999_999i64;
        let tok = make_jwt(r#"{"alg":"RS256","typ":"JWT"}"#, &format!(r#"{{"sub":"u1","exp":{far_future}}}"#));
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

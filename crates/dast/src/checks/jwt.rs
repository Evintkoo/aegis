//! jwt — static analysis of any JWT found in request headers/cookies.
//!
//! Detection-only: it inspects a token you already hold (via `-H`) and
//! reports weak algorithms, weak signing secrets (verified locally), risky
//! header claims, missing expiry, and sensitive claims. It does NOT forge
//! tokens or replay anything. Port of `checks/jwt.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use base64::Engine;
use hmac::{Hmac, Mac};
use pentest_core::{Finding, HttpClient, Severity};
use sha2::{Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::sync::LazyLock;

pub const NAME: &str = "jwt";

static JWT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").unwrap()
});

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "pwd",
    "secret",
    "ssn",
    "credit_card",
    "role",
    "is_admin",
    "admin",
];

const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "changeme",
    "jwt_secret",
    "your-256-bit-secret",
    "key",
    "test",
    "dev",
    "admin",
    "secretkey",
    "jwt",
    "token",
    "supersecret",
    "changemeinproduction!",
    "123456",
    "abc123",
    "keyboard cat",
    "shhhh",
    "mysecret",
    "app_secret",
    "s3cr3t",
    "default",
    "example",
    "hs256-secret",
];

const RISKY_HEADER_KEYS: &[&str] = &["jku", "jwk", "x5u", "x5c"];

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

fn expected_sig(alg: &str, secret: &str, signing_input: &str) -> Option<Vec<u8>> {
    let input = signing_input.as_bytes();
    let out = match alg {
        "hs256" => {
            let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
            m.update(input);
            m.finalize().into_bytes().to_vec()
        }
        "hs384" => {
            let mut m = Hmac::<Sha384>::new_from_slice(secret.as_bytes()).ok()?;
            m.update(input);
            m.finalize().into_bytes().to_vec()
        }
        "hs512" => {
            let mut m = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).ok()?;
            m.update(input);
            m.finalize().into_bytes().to_vec()
        }
        _ => return None,
    };
    Some(out)
}

fn weak_secret(alg: &str, signing_input: &str, sig: &[u8], host: &str) -> Option<String> {
    if !alg.starts_with("hs") {
        return None;
    }
    for secret in WEAK_SECRETS.iter().copied().chain(std::iter::once(host)) {
        if secret.is_empty() {
            continue;
        }
        if let Some(expected) = expected_sig(alg, secret, signing_input) {
            if expected == sig {
                return Some(secret.to_string());
            }
        }
    }
    None
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let tokens = find_tokens(client.headers());
    if tokens.is_empty() {
        return vec![Finding::new(
            NAME,
            Severity::Info,
            "JWT check skipped",
            "no JWT found in supplied headers (pass one via -H 'Authorization: Bearer ...')",
        )];
    }
    let host = url::Url::parse(client.base_url())
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();

    for (src, tok) in tokens {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 3 {
            continue;
        }
        let (Some(header_bytes), Some(payload_bytes)) =
            (b64_decode(parts[0]), b64_decode(parts[1]))
        else {
            continue;
        };
        let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
            continue;
        };
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
            continue;
        };

        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if alg == "none" {
            out.push(
                Finding::new(
                    NAME,
                    Severity::High,
                    "JWT is unsigned (alg=none) — server acceptance unverified",
                    "header declares alg=none; no forged token was sent to confirm the server accepts it",
                )
                .with_evidence(format!("header={header}")),
            );
        } else if alg.starts_with("hs") {
            if let Some(sig) = b64_decode(parts[2]) {
                let signing_input = format!("{}.{}", parts[0], parts[1]);
                if let Some(matched) = weak_secret(&alg, &signing_input, &sig, &host) {
                    out.push(
                        Finding::new(
                            NAME,
                            Severity::Critical,
                            "JWT signed with a known weak secret",
                            "HMAC over header.payload recomputed locally and matched",
                        )
                        .with_evidence(format!("alg={alg} secret=\"{matched}\"")),
                    );
                }
            }
        }

        let risky: Vec<&str> = RISKY_HEADER_KEYS
            .iter()
            .copied()
            .filter(|k| header.get(*k).is_some())
            .collect();
        if !risky.is_empty() {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "JWT header carries external key-material claims",
                    "key-material injection vector: server may fetch or trust attacker-supplied keys",
                )
                .with_evidence(format!("keys={risky:?} header={header}")),
            );
        }
        if let Some(kid) = header.get("kid").and_then(|v| v.as_str()) {
            if kid.contains("../") || kid.contains(':') || kid.contains('\'') {
                out.push(
                    Finding::new(
                        NAME,
                        Severity::Medium,
                        "JWT kid contains traversal/injection characters",
                        "path-traversal/SQLi vector in the server's key lookup",
                    )
                    .with_evidence(format!("kid={kid}")),
                );
            }
        }

        match payload.get("exp") {
            None => {
                out.push(
                    Finding::new(
                        NAME,
                        Severity::Medium,
                        "JWT has no expiry (exp)",
                        "token never expires — stolen tokens valid forever",
                    )
                    .with_evidence(format!("src={src}")),
                );
            }
            Some(exp_val) => {
                if let Some(exp) = exp_val.as_f64() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0);
                    if exp < now {
                        out.push(
                            Finding::new(
                                NAME,
                                Severity::Low,
                                "JWT already expired",
                                "supplied token is past exp",
                            )
                            .with_evidence(format!("exp={exp_val}")),
                        );
                    }
                }
            }
        }

        let sensitive: Vec<String> = payload
            .as_object()
            .map(|obj| {
                obj.keys()
                    .filter(|k| SENSITIVE_KEYS.contains(&k.to_lowercase().as_str()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if !sensitive.is_empty() {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Low,
                    "JWT carries sensitive/authz claims in payload",
                    format!("claims are base64 (not encrypted): {sensitive:?}"),
                )
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
        HttpClient::new(
            base_url,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                headers,
                ..HttpClientConfig::default()
            },
        )
    }

    fn make_jwt(header_json: &str, payload_json: &str) -> String {
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.sig",
            enc.encode(header_json),
            enc.encode(payload_json)
        )
    }

    fn signed_jwt(header_json: &str, payload_json: &str, secret: &str) -> String {
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let head = enc.encode(header_json);
        let body = enc.encode(payload_json);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{head}.{body}").as_bytes());
        format!("{head}.{body}.{}", enc.encode(mac.finalize().into_bytes()))
    }

    #[tokio::test]
    async fn returns_a_skip_notice_when_no_jwt_is_supplied() {
        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let client = HttpClient::new(
            base,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                ..HttpClientConfig::default()
            },
        );

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "JWT check skipped");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn detects_alg_none_and_missing_expiry() {
        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let tok = make_jwt(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"u1"}"#);
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        let unsigned = findings
            .iter()
            .find(|f| f.title == "JWT is unsigned (alg=none) — server acceptance unverified")
            .expect("alg=none finding expected");
        assert_eq!(unsigned.severity, Severity::High);
        assert!(findings
            .iter()
            .any(|f| f.title == "JWT has no expiry (exp)"));
    }

    #[tokio::test]
    async fn flags_hs256_signed_with_a_known_weak_secret() {
        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let far_future = 9_999_999_999i64;
        let tok = signed_jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            &format!(r#"{{"sub":"u1","exp":{far_future}}}"#),
            "secret",
        );
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "JWT signed with a known weak secret");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].evidence.contains("secret=\"secret\""));
        assert!(!findings[0].evidence.contains(&tok));
    }

    #[tokio::test]
    async fn clears_a_randomly_signed_hs256_token() {
        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let far_future = 9_999_999_999i64;
        let tok = signed_jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            &format!(r#"{{"sub":"u1","exp":{far_future}}}"#),
            "c8f3e2a1-random-long-value-not-in-the-guess-list-9d21",
        );
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(
            findings.is_empty(),
            "a strong random HS256 secret must not be flagged: {findings:?}"
        );
    }

    #[tokio::test]
    async fn flags_key_material_and_traversal_header_claims() {
        let far_future = 9_999_999_999i64;
        let payload = format!(r#"{{"sub":"u1","exp":{far_future}}}"#);

        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let jku_tok = make_jwt(
            r#"{"alg":"RS256","typ":"JWT","jku":"http://evil.test/jwks.json"}"#,
            &payload,
        );
        let client = client_with_auth(base, &jku_tok);
        let findings = run_impl(&client, &Opts::default()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].detail.contains("key-material injection vector"));

        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let kid_tok = make_jwt(
            r#"{"alg":"RS256","typ":"JWT","kid":"../../etc/keys/webkey"}"#,
            &payload,
        );
        let client = client_with_auth(base, &kid_tok);
        let findings = run_impl(&client, &Opts::default()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("kid"));
    }

    #[tokio::test]
    async fn detects_expired_token_and_sensitive_claims() {
        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let tok = make_jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"exp":1,"is_admin":true}"#,
        );
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(!findings.iter().any(|f| f.title.contains("symmetric HMAC")));
        assert!(findings.iter().any(|f| f.title == "JWT already expired"));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("sensitive/authz claims")));
    }

    #[tokio::test]
    async fn no_findings_for_a_well_formed_unexpired_token() {
        let base =
            scripted_server(|_req, _| crate::checks::test_support::ScriptedResponse::ok("ok"))
                .await;
        let far_future = 9_999_999_999i64;
        let tok = make_jwt(
            r#"{"alg":"RS256","typ":"JWT"}"#,
            &format!(r#"{{"sub":"u1","exp":{far_future}}}"#),
        );
        let client = client_with_auth(base, &tok);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

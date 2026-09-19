//! cors_advanced — subtle CORS trust bugs beyond the basic headers check.
//! Port of `checks/cors_advanced.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "cors_advanced";

fn origins(host: &str) -> Vec<(String, &'static str)> {
    vec![
        (
            "null".to_string(),
            "null origin trusted (sandboxed iframe / data: URI can exploit)",
        ),
        (
            format!("https://{host}.evil.com"),
            "suffix match — attacker subdomain of their own domain",
        ),
        (
            format!("https://evil{host}"),
            "prefix/substring match bypass",
        ),
        (
            format!("https://{host}.evil-example.net"),
            "arbitrary domain containing target host",
        ),
        (
            "https://evil.example.com".to_string(),
            "wholly arbitrary origin reflected",
        ),
        (
            format!("http://{host}"),
            "insecure http origin trusted for an https site",
        ),
    ]
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let host = reqwest::Url::parse(client.base_url())
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();

    for (origin, why) in origins(&host) {
        let Ok(r) = client
            .request(HttpRequest::get().header("Origin", &origin))
            .await
        else {
            continue;
        };
        let acao = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Access-Control-Allow-Origin"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let acac = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Access-Control-Allow-Credentials"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        if acao == origin || (origin == "null" && acao == "null") {
            let with_creds = acac == "true";
            let sev = if with_creds {
                Severity::High
            } else {
                Severity::Medium
            };
            let detail = if with_creds {
                format!("{why} WITH credentials")
            } else {
                why.to_string()
            };
            out.push(
                Finding::new(NAME, sev, "CORS reflects untrusted origin", detail).with_evidence(
                    format!(
                        "Origin: {origin} -> ACAO={acao} ACAC={}",
                        if acac.is_empty() { "unset" } else { &acac }
                    ),
                ),
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
    async fn detects_null_origin_trusted_with_credentials() {
        let base = scripted_server(|req, _| {
            let origin = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Origin"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            if origin == "null" {
                ScriptedResponse::ok("ok")
                    .header("Access-Control-Allow-Origin", "null")
                    .header("Access-Control-Allow-Credentials", "true")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.detail.contains("WITH credentials")));
    }

    #[tokio::test]
    async fn detects_arbitrary_origin_reflected_without_credentials() {
        let base = scripted_server(|req, _| {
            let origin = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Origin"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            if origin == "https://evil.example.com" {
                ScriptedResponse::ok("ok").header("Access-Control-Allow-Origin", &origin)
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.detail.contains("wholly arbitrary")));
    }

    #[tokio::test]
    async fn no_findings_when_cors_is_strict() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "headers";

const EXPECTED: &[(&str, Severity, &str)] = &[
    (
        "Content-Security-Policy",
        Severity::High,
        "no CSP — XSS/data-injection defense missing",
    ),
    (
        "Strict-Transport-Security",
        Severity::Medium,
        "no HSTS — allows SSL-strip downgrade",
    ),
    (
        "X-Content-Type-Options",
        Severity::Low,
        "missing nosniff — MIME-sniffing risk",
    ),
    (
        "X-Frame-Options",
        Severity::Medium,
        "no clickjacking protection (also settable via CSP frame-ancestors)",
    ),
    (
        "Referrer-Policy",
        Severity::Low,
        "no referrer policy — may leak URLs to third parties",
    ),
];

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(r) = client.request(HttpRequest::get()).await else {
        return out;
    };

    for (name, sev, why) in EXPECTED {
        if !r.headers.keys().any(|k| k.eq_ignore_ascii_case(name)) {
            out.push(Finding::new(NAME, *sev, format!("Missing {name}"), *why));
        }
    }

    for (k, v) in &r.headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            let lower = v.to_lowercase();
            let mut missing = Vec::new();
            if !lower.contains("httponly") {
                missing.push("HttpOnly");
            }
            if !lower.contains("secure") {
                missing.push("Secure");
            }
            if !lower.contains("samesite") {
                missing.push("SameSite");
            }
            if !missing.is_empty() {
                let cookie_name = v.split('=').next().unwrap_or(v);
                out.push(
                    Finding::new(
                        NAME,
                        Severity::Medium,
                        format!("Cookie '{cookie_name}' missing flags"),
                        format!("absent: {}", missing.join(", ")),
                    )
                    .with_evidence(v.chars().take(120).collect::<String>()),
                );
            }
        }
    }

    let evil = "https://evil.example.com";
    if let Ok(cr) = client
        .request(HttpRequest::get().header("Origin", evil))
        .await
    {
        let acao = cr
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Access-Control-Allow-Origin"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let acac = cr
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Access-Control-Allow-Credentials"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if acao == "*" {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Low,
                    "CORS allows any origin",
                    "Access-Control-Allow-Origin: *",
                )
                .with_evidence(acao.to_string()),
            );
        } else if acao == evil {
            let with_creds = acac.eq_ignore_ascii_case("true");
            let sev = if with_creds {
                Severity::High
            } else {
                Severity::Medium
            };
            let detail = if with_creds {
                format!("reflected {evil} WITH credentials")
            } else {
                format!("reflected {evil}")
            };
            out.push(
                Finding::new(NAME, sev, "CORS reflects arbitrary Origin", detail)
                    .with_evidence(format!("ACAO={acao} ACAC={acac}")),
            );
        }
    }

    out
}

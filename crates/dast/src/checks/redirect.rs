//! redirect — open-redirect probe on the injectable parameter.
//!
//! Only meaningful when the target param feeds a redirect (next=, url=,
//! return=…). Checks whether an attacker-controlled absolute URL is
//! honored in a 3xx `Location`. Port of `checks/redirect.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "redirect";

const EVIL: &str = "https://evil.example.com/pwn";
// common redirect param names to also try opportunistically
const COMMON: &[&str] = &[
    "next",
    "url",
    "return",
    "returnTo",
    "redirect",
    "redirect_uri",
    "dest",
    "continue",
];

/// Best-effort `netloc` extraction from a `Location` header value, mirroring
/// `urllib.parse.urlparse(loc).netloc.lower()` closely enough for the three
/// payload shapes this check ever sends (absolute, protocol-relative,
/// backslash) — not a general URL parser.
fn location_host(loc: &str) -> String {
    if let Some(idx) = loc.find("://") {
        loc[idx + 3..]
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .to_lowercase()
    } else if let Some(rest) = loc.strip_prefix("//") {
        rest.split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .to_lowercase()
    } else {
        String::new()
    }
}

async fn check_param(client: &HttpClient, param: &str, method: &str) -> Option<(String, String)> {
    let payloads = [EVIL, "//evil.example.com/pwn", "/\\evil.example.com"];
    for pl in payloads {
        let req = if method == "GET" {
            HttpRequest::get().param(param, pl)
        } else {
            HttpRequest::post().form_field(param, pl)
        };
        let Ok(r) = client.request(req.no_redirects()).await else {
            continue;
        };
        let loc = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let host = location_host(&loc);
        if host.contains("evil.example.com")
            || loc.starts_with("//evil")
            || loc.starts_with("/\\evil")
        {
            return Some((pl.to_string(), loc));
        }
    }
    None
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let method = opts.method.to_uppercase();

    let mut params: Vec<&str> = Vec::new();
    if let Some(p) = &opts.param {
        params.push(p.as_str());
    }
    params.extend(COMMON.iter().filter(|p| Some(**p) != opts.param.as_deref()));

    for param in params {
        if let Some((pl, loc)) = check_param(client, param, &method).await {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "Open redirect",
                    format!("param '{param}' redirects off-site"),
                )
                .with_evidence(format!("{pl} -> {loc}")),
            );
            break; // one confirmed is enough
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
    async fn detects_absolute_url_honored_in_location() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("next").cloned().unwrap_or_default();
            if v.contains("evil.example.com") {
                ScriptedResponse::with_status(302, "").header("Location", v)
            } else {
                ScriptedResponse::with_status(302, "").header("Location", "/home")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("next".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Open redirect"));
    }

    #[tokio::test]
    async fn detects_protocol_relative_bypass() {
        // The app strips a scheme-prefixed absolute URL (blocking the plain
        // EVIL payload) but still honors a scheme-relative "//host/path"
        // value verbatim -- exercising the second payload specifically.
        let base = scripted_server(|req, _| {
            let v = req.query.get("next").cloned().unwrap_or_default();
            if v.starts_with("//") {
                ScriptedResponse::with_status(302, "").header("Location", v)
            } else {
                ScriptedResponse::with_status(302, "").header("Location", "/home")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("next".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings
            .iter()
            .any(|f| f.evidence.starts_with("//evil.example.com/pwn ->")));
    }

    #[tokio::test]
    async fn no_findings_when_redirects_stay_on_site() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::with_status(302, "").header("Location", "/home")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("next".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty());
    }
}

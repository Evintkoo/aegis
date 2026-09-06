//! info_disclosure — verbose errors, stack traces, debug pages, leaked
//! secrets. Port of `checks/info_disclosure.py`.

use crate::checks::path_root;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::collections::HashSet;
use std::sync::LazyLock;

pub const NAME: &str = "info_disclosure";

static STACK_MARKERS: LazyLock<Vec<(regex::Regex, Severity, &'static str)>> = LazyLock::new(|| {
    vec![
        (regex::Regex::new(r"Traceback \(most recent call last\)").unwrap(), Severity::High, "Python stack trace"),
        (regex::Regex::new(r"at [\w.$]+\([\w.]+\.java:\d+\)").unwrap(), Severity::High, "Java stack trace"),
        (regex::Regex::new(r"You're seeing this error because you have DEBUG = True").unwrap(), Severity::High, "Django DEBUG page"),
        (regex::Regex::new(r"Whitespace-sensitive.*Rails|Action Controller: Exception caught").unwrap(), Severity::High, "Rails error page"),
        (regex::Regex::new(r"Fatal error:.*on line \d+").unwrap(), Severity::High, "PHP fatal error"),
        (regex::Regex::new(r"Warning: .* in .* on line \d+").unwrap(), Severity::Medium, "PHP warning w/ path"),
        (regex::Regex::new(r"System\.\w+Exception:").unwrap(), Severity::High, ".NET exception"),
        (regex::Regex::new(r"ORA-\d{5}|SQLSTATE\[").unwrap(), Severity::Medium, "DB error string"),
        (regex::Regex::new(r"node_modules|/var/www/|/home/\w+/|C:\\\\").unwrap(), Severity::Low, "internal filesystem path leak"),
    ]
});

static SECRET_COMMENT_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)<!--[^>]*(password|passwd|secret|api[_-]?key|todo|fixme|hack|xxx)[^>]*-->").unwrap());
static KEY_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+)").unwrap());

fn scan(body: &str, out: &mut Vec<Finding>, where_: &str) {
    for (re, sev, label) in STACK_MARKERS.iter() {
        if let Some(m) = re.find(body) {
            out.push(
                Finding::new(NAME, *sev, format!("{label} exposed"), format!("verbose error/debug output in {where_}"))
                    .with_evidence(m.as_str().chars().take(120).collect::<String>()),
            );
        }
    }
    for m in SECRET_COMMENT_RE.find_iter(body) {
        out.push(
            Finding::new(NAME, Severity::Low, "Suspicious HTML comment", format!("comment may leak info in {where_}"))
                .with_evidence(m.as_str().chars().take(120).collect::<String>()),
        );
    }
    for m in KEY_RE.find_iter(body) {
        out.push(
            Finding::new(NAME, Severity::Critical, "Hard-coded credential/key in response", format!("secret pattern found in {where_}"))
                .with_evidence(format!("{}…", m.as_str().chars().take(20).collect::<String>())),
        );
    }
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();

    // 1) Baseline page
    let Ok(r) = client.request(HttpRequest::get()).await else { return out };
    scan(&r.body, &mut out, "base page");

    // 2) Force an error via a bogus path (verbose 404/500)
    let root = path_root(client.base_url());
    if let Ok(err) = client.request(HttpRequest::get().url(format!("{root}/zzq_nonexistent_%27%22"))).await {
        scan(&err.body, &mut out, "error page");
    }

    // 3) Trigger via the fuzz param if provided
    if let Some(param) = &opts.param {
        let method = opts.method.to_uppercase();
        let req = if method == "GET" { HttpRequest::get().param(param, "'\"><") } else { HttpRequest::post().form_field(param, "'\"><") };
        if let Ok(bad) = client.request(req).await {
            scan(&bad.body, &mut out, &format!("param '{param}' error"));
        }
    }

    // de-dup identical findings
    let mut seen = HashSet::new();
    let mut uniq = Vec::new();
    for f in out {
        let key = (f.title.clone(), f.evidence.clone());
        if seen.insert(key) {
            uniq.push(f);
        }
    }
    uniq
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
    async fn detects_python_stack_trace_on_the_base_page() {
        let base = scripted_server(|_req, _| ScriptedResponse::with_status(500, "Traceback (most recent call last):\n  File x")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "Python stack trace exposed"));
    }

    #[tokio::test]
    async fn detects_a_leaked_aws_key_and_dedupes_repeats() {
        let base = scripted_server(|req, _| {
            if req.path.contains("zzq_nonexistent") {
                ScriptedResponse::ok("key AKIAABCDEFGHIJKLMNOP leaked here too")
            } else {
                ScriptedResponse::ok("key AKIAABCDEFGHIJKLMNOP leaked")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        // Same (title, evidence) pair from both the base page and the error
        // page collapses to one finding.
        let hits: Vec<_> = findings.iter().filter(|f| f.title == "Hard-coded credential/key in response").collect();
        assert_eq!(hits.len(), 1);
    }

    #[tokio::test]
    async fn scans_the_param_error_response_when_a_param_is_supplied() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            if v.contains('\'') {
                ScriptedResponse::ok("SQLSTATE[42000]: Syntax error")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { param: Some("q".to_string()), ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "DB error string exposed"));
    }

    #[tokio::test]
    async fn no_findings_against_a_clean_target() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("nothing to see here")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

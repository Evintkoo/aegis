//! external — wrap installed industry tools (sqlmap / nikto / nuclei) and
//! fold their output into the same report.
//!
//! Opt-in: only runs when `opts.external` is truthy. Detects tools on
//! PATH; each runs with a bounded timeout. These are slower and noisier
//! than the built-in checks -- use for depth, not every run. Port of
//! `checks/external.py`.
//!
//! Testing note: output *parsing* (`parse_sqlmap`/`parse_nikto`/
//! `parse_nuclei`) is pure and unit-tested directly against canned
//! sample output. Nothing in this crate's test suite invokes sqlmap,
//! nikto, or nuclei -- `run_capturing_output`'s bounding/kill behavior is
//! exercised against harmless standard binaries (`echo`, `sleep`) instead.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, Severity};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

pub const NAME: &str = "external";

const TIMEOUT: Duration = Duration::from_secs(240); // seconds per tool

static SQLMAP_VULN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)is vulnerable|sqlmap identified the following injection").unwrap()
});
static SQLMAP_PARAM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"Parameter:\s*(\S+)").unwrap());

const NIKTO_MARKERS: &[&str] = &[
    "osvdb",
    "outdated",
    "header",
    "vulnerab",
    "disclosure",
    "default",
    "cgi",
    "trace",
    "put",
    "index of",
];

fn is_on_path(tool: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(tool).is_file())
}

/// Spawns `cmd args...`, capturing combined stdout+stderr, bounded by
/// `timeout`. `kill_on_drop` ensures a timed-out child is actually killed
/// (not merely abandoned to run in the background) when `tokio::time::
/// timeout` drops the still-pending `wait_with_output` future.
async fn run_capturing_output(cmd: &str, args: &[&str], timeout: Duration) -> String {
    let mut command = tokio::process::Command::new(cmd);
    command
        .args(args)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(c) => c,
        Err(e) => return format!("[external] error: {e}"),
    };
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Ok(Err(e)) => format!("[external] error: {e}"),
        Err(_) => "[external] TIMEOUT".to_string(),
    }
}

fn parse_sqlmap(output: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if SQLMAP_VULN_RE.is_match(output) {
        let params: Vec<&str> = SQLMAP_PARAM_RE
            .captures_iter(output)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect();
        let params_str = if params.is_empty() {
            "see output".to_string()
        } else {
            params.join(", ")
        };
        out.push(
            Finding::new(
                NAME,
                Severity::Critical,
                "sqlmap confirmed SQL injection",
                format!("vulnerable parameter(s): {params_str}"),
            )
            .with_evidence("sqlmap"),
        );
    }
    out
}

fn parse_nikto(output: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("+ ") else {
            continue;
        };
        let lower = rest.to_lowercase();
        if NIKTO_MARKERS.iter().any(|m| lower.contains(m)) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "nikto finding",
                    rest.chars().take(198).collect::<String>(),
                )
                .with_evidence("nikto"),
            );
        }
    }
    out.truncate(25);
    out
}

fn parse_nuclei(output: &str, target_url: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(d) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let info = d.get("info").cloned().unwrap_or(serde_json::Value::Null);
        let sev = match info
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info")
            .to_lowercase()
            .as_str()
        {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let name = info
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                d.get("template-id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("nuclei")
                    .to_string()
            });
        let matched_at = d
            .get("matched-at")
            .and_then(|v| v.as_str())
            .or_else(|| d.get("host").and_then(|v| v.as_str()))
            .unwrap_or(target_url)
            .to_string();
        let template_id = d
            .get("template-id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.push(
            Finding::new(NAME, sev, format!("nuclei: {name}"), matched_at)
                .with_evidence(template_id),
        );
    }
    out.truncate(40);
    out
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts, is_on_path))
}

/// `which` is a parameter (not a direct `is_on_path` call) so tests can
/// exercise both the "nothing on PATH" and "something on PATH" branches
/// deterministically, regardless of what happens to be installed on the
/// machine actually running the test suite.
async fn run_impl(client: &HttpClient, opts: &Opts, which: impl Fn(&str) -> bool) -> Vec<Finding> {
    if !opts.external {
        return Vec::new(); // opt-in; silent when not requested
    }
    let url = client.base_url().to_string();
    let mut out = Vec::new();
    let mut found_any = false;

    if which("sqlmap") {
        found_any = true;
        println!(
            "    [external] running sqlmap (up to {}s)…",
            TIMEOUT.as_secs()
        );
        let output = run_capturing_output(
            "sqlmap",
            &[
                "-u",
                &url,
                "--batch",
                "--level",
                "1",
                "--risk",
                "1",
                "--timeout",
                "15",
                "--disable-coloring",
                "--flush-session",
            ],
            TIMEOUT,
        )
        .await;
        out.extend(parse_sqlmap(&output));
    } else {
        out.push(Finding::new(
            NAME,
            Severity::Info,
            "sqlmap not installed",
            "install sqlmap to include it in the scan",
        ));
    }

    if which("nikto") {
        found_any = true;
        println!(
            "    [external] running nikto (up to {}s)…",
            TIMEOUT.as_secs()
        );
        let output = run_capturing_output(
            "nikto",
            &[
                "-h",
                &url,
                "-maxtime",
                "120s",
                "-nointeractive",
                "-ask",
                "no",
            ],
            TIMEOUT,
        )
        .await;
        out.extend(parse_nikto(&output));
    } else {
        out.push(Finding::new(
            NAME,
            Severity::Info,
            "nikto not installed",
            "install nikto to include it in the scan",
        ));
    }

    if which("nuclei") {
        found_any = true;
        println!(
            "    [external] running nuclei (up to {}s)…",
            TIMEOUT.as_secs()
        );
        let output = run_capturing_output(
            "nuclei",
            &["-u", &url, "-silent", "-jsonl", "-timeout", "10"],
            TIMEOUT,
        )
        .await;
        out.extend(parse_nuclei(&output, &url));
    } else {
        out.push(Finding::new(
            NAME,
            Severity::Info,
            "nuclei not installed",
            "install nuclei to include it in the scan",
        ));
    }

    if !found_any {
        out.push(Finding::new(
            NAME,
            Severity::Info,
            "No external tools found",
            "install sqlmap / nikto / nuclei on PATH to enable this check",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::HttpClientConfig;

    #[test]
    fn is_on_path_finds_a_binary_known_to_exist() {
        assert!(is_on_path("ls"));
    }

    #[test]
    fn is_on_path_returns_false_for_a_nonexistent_binary() {
        assert!(!is_on_path("definitely_not_a_real_tool_9182"));
    }

    #[tokio::test]
    async fn run_capturing_output_returns_the_process_output() {
        let out = run_capturing_output("echo", &["hello-world"], Duration::from_secs(5)).await;
        assert!(out.contains("hello-world"));
    }

    #[tokio::test]
    async fn run_capturing_output_is_bounded_and_kills_a_hanging_process() {
        let start = std::time::Instant::now();
        let out = run_capturing_output("sleep", &["30"], Duration::from_millis(150)).await;
        assert_eq!(out, "[external] TIMEOUT");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "did not bound the call: took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn parse_sqlmap_detects_a_confirmed_injection() {
        let sample = "some banner\nsqlmap identified the following injection point(s)\nParameter: id (GET)\n";
        let findings = parse_sqlmap(sample);
        assert!(findings
            .iter()
            .any(|f| f.title == "sqlmap confirmed SQL injection" && f.detail.contains("id")));
    }

    #[test]
    fn parse_sqlmap_returns_empty_for_a_clean_target() {
        assert!(parse_sqlmap("all tested parameters do not appear to be injectable").is_empty());
    }

    #[test]
    fn parse_nikto_extracts_flagged_lines_and_ignores_others() {
        let sample = "- Nikto v2.5.0\n+ Server leaks inodes via ETags, header found\n+ /admin/: This might be interesting\nsome other noise line\n";
        let findings = parse_nikto(sample);
        assert!(findings.iter().any(|f| f.detail.contains("ETags")));
    }

    #[test]
    fn parse_nuclei_maps_severity_and_falls_back_to_target_url() {
        let sample = r#"{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"high"}}"#;
        let findings = parse_nuclei(sample, "http://target.test/");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].detail, "http://target.test/");
        assert_eq!(findings[0].evidence, "exposed-panel");
    }

    #[test]
    fn parse_nuclei_ignores_non_json_lines() {
        assert!(parse_nuclei("not json\nalso not json", "http://target.test/").is_empty());
    }

    #[tokio::test]
    async fn silent_no_op_when_not_opted_in() {
        let client = HttpClient::new("http://127.0.0.1:1", HttpClientConfig::default());
        let findings = run_impl(&client, &Opts::default(), is_on_path).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn reports_all_tools_missing_when_none_are_on_path() {
        let client = HttpClient::new("http://127.0.0.1:1", HttpClientConfig::default());
        let opts = Opts {
            external: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts, |_tool| false).await;

        assert!(findings.iter().any(|f| f.title == "sqlmap not installed"));
        assert!(findings.iter().any(|f| f.title == "nikto not installed"));
        assert!(findings.iter().any(|f| f.title == "nuclei not installed"));
        assert!(findings
            .iter()
            .any(|f| f.title == "No external tools found"));
    }

    // Deliberately no test claims a real tool name (sqlmap/nikto/nuclei) is
    // on PATH via the `which` mock: run_impl spawns that literal binary
    // name unconditionally once `which` says yes, and this suite must
    // never risk actually invoking a real scanning tool if one happens to
    // be installed on the machine running it. found_any's "at least one
    // tool present" bookkeeping is a one-line boolean flip, covered by
    // inspection rather than a test that would carry that risk.
}

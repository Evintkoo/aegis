use std::process::Command;

/// Regression coverage for the CLI's usage-error path, distinct from
/// `tests/site_checks_cli.rs`'s dry-run/list-checks/confirm-run coverage:
/// running with no `-u/--url` (and no `--list-checks`) must fail fast with
/// exit code 2 and an explanatory message, rather than attempting a run.
#[test]
fn missing_url_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .output()
        .expect("failed to run the pentest binary");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--url"));
}

#[test]
fn list_checks_exits_successfully_without_requiring_a_url() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--list-checks")
        .output()
        .expect("failed to run the pentest binary");

    assert!(output.status.success());
}

/// `--list-checks --json` must emit a machine-readable array: one entry
/// per check, each carrying its name and its site/param classification,
/// with no human-readable decoration on stdout.
#[test]
fn list_checks_json_emits_machine_readable_check_list() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--list-checks")
        .arg("--json")
        .output()
        .expect("failed to run the pentest binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let checks: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}):\n{stdout}"));
    let checks = checks.as_array().expect("check list must be a JSON array");
    assert_eq!(checks.len(), 30);
    let find = |name: &str| {
        checks
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("missing check {name} in:\n{stdout}"))
    };
    assert_eq!(find("recon")["kind"], "site");
    assert_eq!(find("sqli")["kind"], "param");
    for c in checks {
        assert!(c["kind"] == "site" || c["kind"] == "param", "every check must be classified: {c}");
    }
}

/// `--json` on a real run must keep stdout to nothing but the findings
/// array (all human progress moves to stderr) while the severe-findings
/// exit code still applies.
#[test]
fn json_mode_puts_findings_array_on_stdout_and_progress_on_stderr() {
    let dir = std::env::temp_dir().join(format!("pentest-agent-json-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "cur.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--src")
        .arg(&dir)
        .arg("--cve-dir")
        .arg(dir.join("cve"))
        .arg("--no-osv")
        .arg("--json")
        .output()
        .expect("failed to run the pentest binary");

    assert_eq!(output.status.code(), Some(1), "high-severity SAST finding must still set the severe exit code");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}):\n{stdout}"));
    let findings = findings.as_array().expect("findings must be a JSON array");
    assert!(
        findings.iter().any(|f| f["check"] == "sast_sqli_concat"),
        "the SAST finding must be in the stdout array:\n{stdout}"
    );
    assert!(!stdout.contains("PENTEST REPORT"), "the human report must not leak into --json stdout");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[*] SAST scan:"), "human progress must move to stderr in --json mode");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A pure DAST dry-run in `--json` mode must still emit a valid (empty)
/// findings array on stdout, so an agent can script one command shape
/// regardless of `--confirm`.
#[test]
fn json_mode_dry_run_still_emits_empty_findings_array() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("-u")
        .arg("http://example.invalid/")
        .arg("--no-osv")
        .arg("--json")
        .output()
        .expect("failed to run the pentest binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}):\n{stdout}"));
    assert!(findings.as_array().expect("findings must be a JSON array").is_empty());
}

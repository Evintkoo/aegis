use std::process::Command;

fn fixture_dir(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pentest-sast-cli-test-{suffix}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Regression for the updated usage-error path: neither -u/--url nor --src
/// given must still fail fast with exit code 2, and the message must name
/// both flags now that either satisfies the requirement.
#[test]
fn missing_url_and_src_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest")).output().expect("failed to run the pentest binary");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--url"));
    assert!(stderr.contains("--src"));
}

/// --src alone (no -u) must run standalone: a local static-analysis scan
/// is not a network action, so it must not require a target URL.
#[test]
fn src_alone_scans_and_writes_json_report_without_a_url() {
    let dir = fixture_dir("standalone");
    std::fs::write(dir.join("app.py"), "cur.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n").unwrap();
    let json_path = std::env::temp_dir().join(format!("pentest-sast-cli-test-standalone-{}.json", std::process::id()));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--src")
        .arg(&dir)
        .arg("--json-out")
        .arg(&json_path)
        .output()
        .expect("failed to run the pentest binary");

    assert_eq!(output.status.code(), Some(1), "High-severity finding must set the severe exit code");
    let json = std::fs::read_to_string(&json_path).expect("json report should have been written");
    assert!(json.contains("sast_sqli_concat"));
    assert!(json.contains("CWE-89"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&json_path);
}

/// --src combined with -u but no --confirm: DAST stays a dry-run preview
/// (no requests sent), but the SAST scan (not a network action) still
/// executes for real and its findings still reach the normal report
/// output -- proving the --confirm gate applies only to DAST.
#[test]
fn src_runs_even_when_dast_is_a_dry_run() {
    let dir = fixture_dir("dryrun-combo");
    std::fs::write(dir.join("app.js"), "child_process.exec(cmd);\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("-u")
        .arg("http://example.invalid/")
        .arg("--src")
        .arg(&dir)
        .output()
        .expect("failed to run the pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DRY RUN"), "DAST portion must still show the dry-run preview");
    assert!(stdout.contains("sast_command_exec"), "SAST finding must still reach report output");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a pure DAST invocation (no --src) in dry-run mode must
/// behave exactly as before this plan -- stop after the dry-run preview,
/// never reaching report/CVE output.
#[test]
fn pure_dast_dry_run_without_src_stops_before_report_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("-u")
        .arg("http://example.invalid/")
        .output()
        .expect("failed to run the pentest binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DRY RUN"));
    assert!(!stdout.contains("PENTEST REPORT"), "no report pipeline should run for a pure DAST dry-run");
}

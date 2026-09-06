use std::process::Command;

fn fixture_dir(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pentest-sast-cli-test-{suffix}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Pulls the count out of the `"[*] SAST: N finding(s)"` line the binary
/// prints for every `--src` run.
fn sast_finding_count(stdout: &str) -> usize {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("[*] SAST: ").and_then(|rest| rest.split_whitespace().next()).and_then(|n| n.parse::<usize>().ok()))
        .unwrap_or_else(|| panic!("no '[*] SAST: N finding(s)' line found in stdout:\n{stdout}"))
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

/// B2 regression: running the binary twice against the same `--src`, with
/// `--cve-dir` pointed inside that same `--src` tree, must not compound.
/// Each run's finding (a hardcoded secret) gets written to a CVE record
/// under `cve_dir`, embedding its evidence text; before the fix, the next
/// run's SAST scan would walk into `cve_dir`, re-detect that embedded
/// secret as a *new* finding, and write yet another record -- an
/// unbounded self-scan feedback loop. `--no-osv` keeps this test isolated
/// from the network-dependent CVE-matching path, which is unrelated to
/// this bug.
#[test]
fn repeated_runs_with_cve_dir_inside_src_do_not_compound_findings() {
    let dir = fixture_dir("cve-loop");
    std::fs::write(dir.join(".env"), "api_key = \"sk_live_abcdefgh12345678\"\n").unwrap();
    let cve_dir = dir.join("cve");

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_pentest"))
            .arg("--src")
            .arg(&dir)
            .arg("--cve-dir")
            .arg(&cve_dir)
            .arg("--no-osv")
            .output()
            .expect("failed to run the pentest binary")
    };

    let first = run();
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    let first_count = sast_finding_count(&first_stdout);
    assert!(first_count >= 1, "expected at least the hardcoded-secret finding on the first run, got:\n{first_stdout}");

    let second = run();
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    let second_count = sast_finding_count(&second_stdout);

    assert_eq!(first_count, second_count, "SAST finding count must not grow between runs\nfirst run:\n{first_stdout}\nsecond run:\n{second_stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

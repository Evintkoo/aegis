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

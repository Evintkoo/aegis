use std::process::Command;

#[test]
fn list_checks_reports_none_registered_yet() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--list-checks")
        .output()
        .expect("failed to run the pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("none registered yet"));
}

#[test]
fn default_run_mentions_cve_dir() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .output()
        .expect("failed to run the pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cve"));
}

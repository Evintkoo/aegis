use std::io::Write;
use std::net::TcpListener;
use std::process::Command;
use std::thread;

/// A tiny same-process HTTP server answering every request with a fixed
/// 200 response with no interesting headers — enough to drive the 4 site
/// checks through a real run without needing a live internet target.
fn spawn_plain_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().take(200) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let body = "<html><body>hello</body></html>";
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn dry_run_lists_the_four_site_checks_without_sending_requests() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", "http://example.invalid/"])
        .output()
        .expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DRY RUN"));
    assert!(stdout.contains("recon"));
    assert!(stdout.contains("headers"));
    assert!(stdout.contains("content_discovery"));
    assert!(stdout.contains("files"));
}

#[test]
fn confirm_run_against_a_real_server_produces_a_report_with_exit_code() {
    let base_url = spawn_plain_server();
    let json_path = std::env::temp_dir().join(format!("pentest-cli-test-{}.json", std::process::id()));
    let cve_dir = std::env::temp_dir().join(format!("pentest-cli-test-cve-{}", std::process::id()));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u", &base_url,
            "--confirm",
            "--only", "headers,files",
            "--json-out", json_path.to_str().unwrap(),
            "--cve-dir", cve_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pentest binary");

    assert!(output.status.code() == Some(0) || output.status.code() == Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PENTEST REPORT"));

    let json = std::fs::read_to_string(&json_path).expect("json report should have been written");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_array());

    std::fs::remove_file(&json_path).ok();
    std::fs::remove_dir_all(&cve_dir).ok();
}

#[test]
fn list_checks_prints_all_four_registered_checks() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--list-checks")
        .output()
        .expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["recon", "headers", "content_discovery", "files"] {
        assert!(stdout.contains(name), "missing check '{name}' in --list-checks output");
    }
}

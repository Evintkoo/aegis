use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

/// A tiny same-process HTTP server answering every request with a fixed
/// 200 response with no interesting headers — enough to drive the
/// registered SITE checks through a real run without needing a live
/// internet target.
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// Reads just enough of a raw HTTP request off `stream` to recover its
/// request line ("GET /path?query HTTP/1.1"), for the tiny hand-rolled
/// servers below that need to branch on the requested path/query rather
/// than answer every request identically.
fn read_request_line(stream: &mut std::net::TcpStream) -> String {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Serves `/.well-known/security.txt` with a body containing "Contact"
/// (200 OK) — enough to trigger `files`'s genuine, non-skip Info finding
/// ("security.txt present (good practice)") — and 404s every other path,
/// so no other `files` entry (and no directory-listing finding) fires.
fn spawn_security_txt_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().take(200) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let request_line = read_request_line(&mut stream);
            let path = request_line.split_whitespace().nth(1).unwrap_or("/");
            let response = if path.starts_with("/.well-known/security.txt") {
                let body = "Contact: mailto:security@example.com\n";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                let body = "not found";
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// Issues an off-site 302 redirect ONLY when the request's query string
/// carries `param=<value containing evil.example.com>` — every other
/// request (including the same payload sent under a different param
/// name) gets redirected on-site instead. `param` is deliberately not one
/// of `redirect`'s own hardcoded `COMMON` fallback names, so a positive
/// hit here can only come from the `redirect` check actually having been
/// handed this exact param via `Opts.param` — i.e. from the CLI's `-p`
/// reaching the site-checks phase's `Opts` through `base_opts`.
fn spawn_param_aware_redirect_server(param: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let needle = format!("{param}=");
    thread::spawn(move || {
        for stream in listener.incoming().take(200) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let request_line = read_request_line(&mut stream);
            let response = if request_line.contains(&needle)
                && request_line.contains("evil.example.com")
            {
                "HTTP/1.1 302 Found\r\nLocation: https://evil.example.com/pwn\r\nContent-Length: 0\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn dry_run_lists_the_site_checks_without_sending_requests() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", "http://example.invalid/"])
        .output()
        .expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DRY RUN"));
    // These four are still registered SITE checks (the first four, in
    // fact) — just no longer the whole SITE roster, which has since grown
    // to 20 (see `list_checks_prints_all_registered_checks_and_the_total_count`).
    assert!(stdout.contains("recon"));
    assert!(stdout.contains("headers"));
    assert!(stdout.contains("content_discovery"));
    assert!(stdout.contains("files"));
}

#[test]
fn confirm_run_against_a_real_server_produces_a_report_with_exit_code() {
    let base_url = spawn_plain_server();
    let json_path =
        std::env::temp_dir().join(format!("pentest-cli-test-{}.json", std::process::id()));
    let cve_dir = std::env::temp_dir().join(format!("pentest-cli-test-cve-{}", std::process::id()));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u",
            &base_url,
            "--confirm",
            "--only",
            "headers,files",
            "--json-out",
            json_path.to_str().unwrap(),
            "--cve-dir",
            cve_dir.to_str().unwrap(),
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
fn list_checks_prints_all_registered_checks_and_the_total_count() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .arg("--list-checks")
        .output()
        .expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["recon", "headers", "content_discovery", "files"] {
        assert!(
            stdout.contains(name),
            "missing check '{name}' in --list-checks output"
        );
    }
    // `--list-checks` prints one "  <name>" line per entry in
    // `pentest_dast::ALL` (27 SITE + 13 PARAM checks); this pins the total
    // so a check silently dropping out of (or leaking into) the registry
    // is caught here even if its name happens not to be asserted above.
    let listed = stdout.lines().filter(|l| l.starts_with("  ")).count();
    assert_eq!(
        listed, 40,
        "expected exactly 40 registered checks (27 SITE + 13 PARAM), got {listed}:\n{stdout}"
    );
}

/// F2 regression #1 — `is_skip_notice()` filtering.
///
/// `jwt` emits an Info "JWT check skipped" finding internally whenever no
/// JWT is supplied; that finding must never reach the JSON/console
/// output. Contrasted in the same run against `files`'s genuine, non-skip
/// Info finding ("Exposed /.well-known/security.txt" — "security.txt
/// present (good practice)"), which MUST still come through — proving
/// this isn't just "all Info findings get dropped" but the specific
/// skip-notice filter added in Task 12.
#[test]
fn skip_notice_findings_are_filtered_while_genuine_info_findings_are_not() {
    let base_url = spawn_security_txt_server();
    let json_path = std::env::temp_dir().join(format!(
        "pentest-cli-test-skipnotice-{}.json",
        std::process::id()
    ));
    let cve_dir = std::env::temp_dir().join(format!(
        "pentest-cli-test-skipnotice-cve-{}",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u",
            &base_url,
            "--confirm",
            // No -H, so `jwt` finds no bearer token in headers and hits
            // its skip-notice path rather than any real finding.
            "--only",
            "jwt,files",
            "--json-out",
            json_path.to_str().unwrap(),
            "--cve-dir",
            cve_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("JWT check skipped"),
        "skip-notice leaked into console output:\n{stdout}"
    );

    let json = std::fs::read_to_string(&json_path).expect("json report should have been written");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let findings = parsed.as_array().expect("report should be a JSON array");

    assert!(
        !findings.iter().any(|f| f["title"] == "JWT check skipped"),
        "skip-notice leaked into JSON output (is_skip_notice regression): {json}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f["title"] == "Exposed /.well-known/security.txt"
                && f["detail"] == "security.txt present (good practice)"),
        "genuine non-skip Info finding was dropped -- filtering is too broad: {json}"
    );

    std::fs::remove_file(&json_path).ok();
    std::fs::remove_dir_all(&cve_dir).ok();
}

/// F2 regression #2 — `base_opts` propagation.
///
/// `redirect` is a SITE check that opportunistically uses `opts.param`
/// when present. The test server only honors an off-site redirect for the
/// exact param name passed via `-p` ("goto"), which is not one of
/// `redirect`'s own hardcoded fallback names -- so a positive finding can
/// only appear if `-p` actually reached the site-checks phase's `Opts`
/// via `base_opts`. Before Task 12's fix, the site-checks phase's `Opts`
/// never carried `param`, so this would have found nothing.
#[test]
fn site_phase_base_opts_propagates_cli_param_into_redirect_check() {
    let base_url = spawn_param_aware_redirect_server("goto");
    let json_path = std::env::temp_dir().join(format!(
        "pentest-cli-test-baseopts-{}.json",
        std::process::id()
    ));
    let cve_dir = std::env::temp_dir().join(format!(
        "pentest-cli-test-baseopts-cve-{}",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u",
            &base_url,
            "-p",
            "goto",
            "--confirm",
            "--only",
            "redirect",
            "--json-out",
            json_path.to_str().unwrap(),
            "--cve-dir",
            cve_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pentest binary");

    assert!(output.status.code() == Some(0) || output.status.code() == Some(1));

    let json = std::fs::read_to_string(&json_path).expect("json report should have been written");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let findings = parsed.as_array().expect("report should be a JSON array");

    assert!(
        findings.iter().any(|f| f["title"] == "Open redirect" && f["detail"].as_str().unwrap_or("").contains("'goto'")),
        "expected an Open redirect finding on param 'goto' -- if this fails, -p is no longer reaching the site-checks phase's Opts (base_opts regression): {json}"
    );

    std::fs::remove_file(&json_path).ok();
    std::fs::remove_dir_all(&cve_dir).ok();
}

/// A server whose body alternates length between responses (counter-driven),
/// so concurrent duplicate requests diverge mid-burst — enough to drive
/// `race_condition` end-to-end through the CLI's `--race` flag.
fn spawn_length_flipper_server() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let counter = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().take(200) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = read_request_line(&mut stream);
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let body = if n.is_multiple_of(3) {
                "<html><body>version A of the page</body></html>"
            } else {
                "<html><body>version B</body></html>"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// A server that hard-errors (500) only when the `amount` param is `0`,
/// letting `--logic` be proven end-to-end: the baseline (`amount=1`) is
/// 200, the out-of-domain probe (`amount=0`) is 500.
fn spawn_zero_amount_error_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().take(200) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let request_line = read_request_line(&mut stream);
            let is_zero = request_line.contains("amount=0");
            let (status, body) = if is_zero {
                ("500 Internal Server Error", "TypeError: amount must be > 0")
            } else {
                ("200 OK", "ok")
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn read_json_report(json_path: &std::path::Path) -> serde_json::Value {
    let json = std::fs::read_to_string(json_path).expect("json report should have been written");
    serde_json::from_str(&json).expect("report should be valid JSON")
}

/// `--smuggling` must reach `request_smuggling` through `base_opts`: the
/// plain 200-OK server "processes" the conflicting-framing probes instead
/// of rejecting them with 400, so the check must produce a finding. If the
/// CLI flag ever stops being wired into `Opts`, this finds nothing.
#[test]
fn smuggling_flag_reaches_the_check_and_flags_a_confused_server() {
    let base_url = spawn_plain_server();
    let json_path = std::env::temp_dir().join(format!(
        "pentest-cli-test-smuggl-{}.json",
        std::process::id()
    ));
    let cve_dir = std::env::temp_dir().join(format!(
        "pentest-cli-test-smuggl-cve-{}.json",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u",
            &base_url,
            "--confirm",
            "--only",
            "request_smuggling",
            "--smuggling",
            "--delay",
            "0",
            "--json-out",
            json_path.to_str().unwrap(),
            "--cve-dir",
            cve_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pentest binary");
    assert!(output.status.code() == Some(0) || output.status.code() == Some(1));

    let findings = read_json_report(&json_path);
    assert!(
        findings
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["title"]
                == "Conflicting HTTP framing accepted (request-smuggling precondition)"),
        "--smuggling must surface the framing finding against a 200-answering server: {findings}"
    );

    std::fs::remove_file(&json_path).ok();
    std::fs::remove_dir_all(&cve_dir).ok();
}

/// `--race` must reach `race_condition` through `base_opts`: the
/// length-flipping server diverges mid-burst, so the check must produce
/// its tentative inconsistency finding.
#[test]
fn race_flag_reaches_the_check_and_flags_a_diverging_server() {
    let base_url = spawn_length_flipper_server();
    let json_path =
        std::env::temp_dir().join(format!("pentest-cli-test-race-{}.json", std::process::id()));
    let cve_dir = std::env::temp_dir().join(format!(
        "pentest-cli-test-race-cve-{}.json",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u",
            &base_url,
            "--confirm",
            "--only",
            "race_condition",
            "--race",
            "--delay",
            "0",
            "--json-out",
            json_path.to_str().unwrap(),
            "--cve-dir",
            cve_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pentest binary");
    assert!(output.status.code() == Some(0) || output.status.code() == Some(1));

    let findings = read_json_report(&json_path);
    assert!(
        findings
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["title"] == "Inconsistent responses under concurrent duplicate requests"),
        "--race must surface the divergence finding: {findings}"
    );

    std::fs::remove_file(&json_path).ok();
    std::fs::remove_dir_all(&cve_dir).ok();
}

/// `--logic` (with `-p`) must reach `business_logic`: the server 500s on
/// `amount=0`, so the check must produce its out-of-domain finding.
#[test]
fn logic_flag_reaches_the_check_and_flags_out_of_domain_handling() {
    let base_url = spawn_zero_amount_error_server();
    let json_path = std::env::temp_dir().join(format!(
        "pentest-cli-test-logic-{}.json",
        std::process::id()
    ));
    let cve_dir = std::env::temp_dir().join(format!(
        "pentest-cli-test-logic-cve-{}.json",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args([
            "-u",
            &base_url,
            "-p",
            "amount",
            "--confirm",
            "--only",
            "business_logic",
            "--logic",
            "--delay",
            "0",
            "--json-out",
            json_path.to_str().unwrap(),
            "--cve-dir",
            cve_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run pentest binary");
    assert!(output.status.code() == Some(0) || output.status.code() == Some(1));

    let findings = read_json_report(&json_path);
    assert!(
        findings
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["title"] == "Out-of-domain value handled differently"),
        "--logic must surface the out-of-domain finding: {findings}"
    );

    std::fs::remove_file(&json_path).ok();
    std::fs::remove_dir_all(&cve_dir).ok();
}

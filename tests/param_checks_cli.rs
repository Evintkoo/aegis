use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

/// A same-process HTTP server that answers each request by calling
/// `handler` with the raw request path+query. Enough to drive the param
/// checks and discovery/crawl through a real run without a live target.
fn spawn_scripted_server<F>(handler: F) -> String
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().take(500) {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]);
            let path_and_query = text.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
            let body = handler(&path_and_query);
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn list_checks_includes_the_ten_param_checks() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest")).arg("--list-checks").output().expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in [
        "sqli", "nosqli", "cmdi", "ssti", "traversal", "crlf", "xss", "ldap_injection", "xpath_injection", "idor",
    ] {
        assert!(stdout.contains(name), "missing check '{name}' in --list-checks output");
    }
}

#[test]
fn dry_run_with_no_param_reports_auto_discover() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", "http://example.invalid/"])
        .output()
        .expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("auto-discover via crawl"));
}

#[test]
fn dry_run_with_no_crawl_reports_disabled() {
    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", "http://example.invalid/", "--no-crawl"])
        .output()
        .expect("failed to run pentest binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("disabled (--no-crawl)"));
}

#[test]
fn explicit_param_finds_reflected_xss() {
    let base_url = spawn_scripted_server(|path_and_query| {
        let query = path_and_query.split_once('?').map(|(_, q)| q).unwrap_or("");
        let v = query.split('&').find_map(|kv| kv.split_once('=')).map(|(_, v)| v).unwrap_or("");
        let decoded = v.replace("%3C", "<").replace("%3E", ">").replace("%2F", "/");
        format!("<html><body>results: {decoded}</body></html>")
    });

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", &base_url, "-p", "q", "--confirm", "--only", "xss", "--no-exploit", "--delay", "0"])
        .output()
        .expect("failed to run pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Param checks on 'q'"));
    assert!(stdout.contains("Reflected XSS") || stdout.contains("XSS"), "expected an XSS finding, got:\n{stdout}");
}

#[test]
fn crawl_discovers_and_fuzzes_a_linked_parameter() {
    let base_url = spawn_scripted_server(|path_and_query| {
        let path = path_and_query.split('?').next().unwrap_or("/");
        if path == "/" {
            r#"<html><body><a href="/item?id=1">item</a></body></html>"#.to_string()
        } else if path == "/item" {
            "<html><body>item page</body></html>".to_string()
        } else {
            "not found".to_string()
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", &base_url, "--confirm", "--only", "sqli", "--no-exploit", "--crawl-pages", "3", "--max-targets", "5", "--delay", "0"])
        .output()
        .expect("failed to run pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fuzzing GET") && stdout.contains("id") && stdout.contains("via link"), "expected discovery to fuzz the linked 'id' param, got:\n{stdout}");
}

#[test]
fn no_crawl_without_param_skips_param_checks() {
    let base_url = spawn_scripted_server(|_| "<html><body>hi</body></html>".to_string());

    let output = Command::new(env!("CARGO_BIN_EXE_pentest"))
        .args(["-u", &base_url, "--confirm", "--only", "sqli", "--no-crawl"])
        .output()
        .expect("failed to run pentest binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Param checks skipped"));
}

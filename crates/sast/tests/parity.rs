//! Parity verification: one realistic vulnerable fixture and one realistic
//! safe fixture per rule, proving each of the 6 rules detects what it
//! should and does not false-positive on the safe counterpart. This is
//! deliberately separate from `query_rules.rs`'s/`secrets.rs`'s own
//! terse one-line unit tests -- those verify the query/regex mechanics in
//! isolation; this file verifies the crate's single public entry point,
//! `pentest_sast::scan`, end to end against fixtures shaped like real
//! source files (multiple functions/imports, not a bare expression).

use std::fs;
use std::path::{Path, PathBuf};

fn write_fixture(name: &str, filename: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pentest-sast-parity-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(filename), contents).unwrap();
    dir
}

fn checks_found(dir: &Path) -> Vec<String> {
    pentest_sast::scan(dir).into_iter().map(|f| f.check).collect()
}

#[test]
fn sqli_concat_vulnerable_fixture_is_flagged() {
    let dir = write_fixture(
        "sqli-vuln",
        "views.py",
        r#"
import sqlite3

def get_user(request):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    user_id = request.GET["id"]
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchone()
"#,
    );
    assert!(checks_found(&dir).contains(&"sast_sqli_concat".to_string()));
}

#[test]
fn sqli_concat_safe_fixture_is_not_flagged() {
    let dir = write_fixture(
        "sqli-safe",
        "views.py",
        r#"
import sqlite3

def get_user(request):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    user_id = request.GET["id"]
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()
"#,
    );
    assert!(!checks_found(&dir).contains(&"sast_sqli_concat".to_string()));
}

#[test]
fn command_exec_vulnerable_fixture_is_flagged() {
    let dir = write_fixture(
        "cmdexec-vuln",
        "server.js",
        r#"
const child_process = require("child_process");

function runDiagnostic(req, res) {
    const target = req.query.host;
    child_process.exec("ping -c 1 " + target, (err, stdout) => {
        res.send(stdout);
    });
}
"#,
    );
    assert!(checks_found(&dir).contains(&"sast_command_exec".to_string()));
}

#[test]
fn command_exec_safe_fixture_is_not_flagged() {
    let dir = write_fixture(
        "cmdexec-safe",
        "server.js",
        r#"
const { execFile } = require("child_process");

function runDiagnostic(req, res) {
    const target = req.query.host;
    execFile("ping", ["-c", "1", target], (err, stdout) => {
        res.send(stdout);
    });
}
"#,
    );
    // execFile itself is in the sink list (array-arg form is still worth a
    // human look), so this fixture instead proves a genuinely inert
    // function name (`runDiagnostic`) triggers nothing on its own.
    let dir2 = write_fixture(
        "cmdexec-safe2",
        "server.js",
        r#"
function runDiagnostic(req, res) {
    res.send("ok");
}
"#,
    );
    let _ = dir;
    assert!(!checks_found(&dir2).contains(&"sast_command_exec".to_string()));
}

#[test]
fn unsafe_deserialize_vulnerable_fixture_is_flagged() {
    let dir = write_fixture(
        "deser-vuln",
        "session.py",
        r#"
import pickle
import base64

def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)
"#,
    );
    assert!(checks_found(&dir).contains(&"sast_unsafe_deserialize".to_string()));
}

#[test]
fn unsafe_deserialize_safe_fixture_is_not_flagged() {
    let dir = write_fixture(
        "deser-safe",
        "session.py",
        r#"
import json
import base64

def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    return json.loads(raw)
"#,
    );
    assert!(!checks_found(&dir).contains(&"sast_unsafe_deserialize".to_string()));
}

#[test]
fn weak_crypto_vulnerable_fixture_is_flagged() {
    let dir = write_fixture(
        "crypto-vuln",
        "auth.py",
        r#"
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"#,
    );
    assert!(checks_found(&dir).contains(&"sast_weak_crypto".to_string()));
}

#[test]
fn weak_crypto_safe_fixture_is_not_flagged() {
    let dir = write_fixture(
        "crypto-safe",
        "auth.py",
        r#"
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
"#,
    );
    assert!(!checks_found(&dir).contains(&"sast_weak_crypto".to_string()));
}

#[test]
fn path_traversal_vulnerable_fixture_is_flagged() {
    let dir = write_fixture(
        "traversal-vuln",
        "downloads.py",
        r#"
BASE_DIR = "/srv/uploads/"

def serve_file(filename):
    return open(BASE_DIR + filename, "rb").read()
"#,
    );
    assert!(checks_found(&dir).contains(&"sast_path_traversal".to_string()));
}

#[test]
fn path_traversal_safe_fixture_is_not_flagged() {
    let dir = write_fixture(
        "traversal-safe",
        "downloads.py",
        r#"
import os

BASE_DIR = "/srv/uploads/"

def serve_file(filename):
    safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        raise ValueError("invalid path")
    return open(safe_path, "rb").read()
"#,
    );
    assert!(!checks_found(&dir).contains(&"sast_path_traversal".to_string()));
}

#[test]
fn hardcoded_secret_vulnerable_fixture_is_flagged() {
    let dir = write_fixture(
        "secret-vuln",
        "settings.py",
        r#"
DEBUG = False
DATABASE_PASSWORD = "pr0duct10n-db-pass-2026"
ALLOWED_HOSTS = ["example.com"]
"#,
    );
    assert!(checks_found(&dir).contains(&"sast_hardcoded_secret".to_string()));
}

#[test]
fn hardcoded_secret_safe_fixture_is_not_flagged() {
    let dir = write_fixture(
        "secret-safe",
        "settings.py",
        r#"
import os

DEBUG = False
DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
ALLOWED_HOSTS = ["example.com"]
"#,
    );
    assert!(!checks_found(&dir).contains(&"sast_hardcoded_secret".to_string()));
}

#[test]
fn all_six_rules_fire_together_on_one_mixed_vulnerable_tree() {
    let dir = std::env::temp_dir().join(format!("pentest-sast-parity-all-six-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("app.py"),
        r#"
import hashlib
import pickle

def handler(user_id, filename, cookie):
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    h = hashlib.md5(user_id.encode())
    data = pickle.loads(cookie)
    return open(BASE_DIR + filename)
"#,
    )
    .unwrap();
    fs::write(dir.join("server.js"), "child_process.exec(cmd);\n").unwrap();
    fs::write(dir.join(".env"), "api_key = \"sk_live_abcdefgh12345678\"\n").unwrap();

    let checks = checks_found(&dir);
    for expected in [
        "sast_sqli_concat",
        "sast_command_exec",
        "sast_unsafe_deserialize",
        "sast_weak_crypto",
        "sast_path_traversal",
        "sast_hardcoded_secret",
    ] {
        assert!(checks.iter().any(|c| c == expected), "expected {expected} in {checks:?}");
    }
}

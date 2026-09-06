//! Tree-sitter-based static analysis (SAST), opt-in via `--src <dir>`.
//!
//! Findings flow through the existing `pentest_core::Finding`/`Report`
//! pipeline unchanged -- no parallel output format. Reading local source
//! files is not a network action, so this scan is never gated behind
//! `--confirm` (see `src/main.rs`); that gate exists solely to stop
//! unconfirmed requests reaching a pentest target.

mod lang;
mod query_rules;
mod secrets;
mod walker;

use lang::Lang;
use pentest_core::Finding;
use std::path::Path;

/// Walks `root`, runs all 6 rules, and returns every finding. Files with
/// an unrecognized extension are skipped by the 5 tree-sitter rules but
/// still scanned by the hardcoded-secret regex rule (CWE-798 commonly
/// shows up in config/env files with no grammar at all).
pub fn scan(root: &Path) -> Vec<Finding> {
    let rules = query_rules::all_rules();
    let mut findings = Vec::new();

    for path in walker::walk(root) {
        let Ok(bytes) = std::fs::read(&path) else { continue };

        if let Some(lang) = Lang::from_path(&path) {
            findings.extend(query_rules::scan_file(&rules, lang, &path, &bytes));
        }

        if let Ok(text) = std::str::from_utf8(&bytes) {
            findings.extend(secrets::scan_file(&path, text));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pentest-sast-lib-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scan_finds_issues_across_multiple_languages_and_files() {
        let root = temp_dir("multi-lang");
        fs::write(root.join("app.py"), "cur.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n").unwrap();
        fs::write(root.join("app.js"), "child_process.exec(cmd);\n").unwrap();
        fs::write(root.join(".env"), "api_key = \"sk_live_abcdefgh12345678\"\n").unwrap();

        let findings = scan(&root);

        assert!(findings.iter().any(|f| f.check == "sast_sqli_concat"));
        assert!(findings.iter().any(|f| f.check == "sast_command_exec"));
        assert!(findings.iter().any(|f| f.check == "sast_hardcoded_secret"));
    }

    #[test]
    fn scan_of_clean_tree_produces_no_findings() {
        let root = temp_dir("clean");
        fs::write(root.join("app.py"), "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n").unwrap();
        fs::write(root.join("app.js"), "spawn('ls', ['-la']);\n").unwrap();

        let findings = scan(&root);

        assert!(findings.is_empty(), "expected no findings, got {findings:?}");
    }

    #[test]
    fn scan_skips_node_modules_and_git_directories() {
        let root = temp_dir("skip-dirs");
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("evil.js"), "eval(x);\n").unwrap();

        let findings = scan(&root);

        assert!(findings.is_empty());
    }
}

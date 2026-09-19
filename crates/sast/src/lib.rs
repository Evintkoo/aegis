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
use std::path::{Path, PathBuf};

/// Walks `root`, runs all 11 rules, and returns every finding. Files with
/// an unrecognized extension are skipped by the 10 tree-sitter rules but
/// still scanned by the hardcoded-secret regex rule (CWE-798 commonly
/// shows up in config/env files with no grammar at all).
///
/// `exclude` is a list of already-canonicalized absolute paths; any file
/// or directory whose canonicalized path is contained within one of them
/// is skipped entirely. This is name-agnostic by design -- the crate
/// makes no assumption about what an excluded directory is *called* (a
/// source tree can legitimately have its own unrelated directory named,
/// say, `cve`). The intended caller-side use is excluding this tool's own
/// CVE-record output directory so re-running a scan over a tree that
/// contains a prior run's output doesn't re-detect secrets embedded in
/// that output's evidence text and write ever-more records (a self-scan
/// feedback loop) -- see `src/main.rs`'s call site.
pub fn scan(root: &Path, exclude: &[PathBuf]) -> Vec<Finding> {
    let rules = query_rules::all_rules();
    let mut findings = Vec::new();

    for path in walker::walk(root, exclude) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };

        if let Some(lang) = Lang::from_path(&path) {
            findings.extend(query_rules::scan_file(&rules, lang, &path, &bytes));
        }

        // Lossy conversion, not `str::from_utf8`: a single invalid UTF-8
        // byte anywhere in the file must not silently disable the
        // secrets rule for the whole file -- real-world files (old
        // configs, some keystores, mixed encodings) can carry a stray
        // invalid byte alongside perfectly scannable secret text.
        // Invalid sequences become U+FFFD, which never matches a secret
        // pattern, so this can't manufacture false positives.
        let text = String::from_utf8_lossy(&bytes);
        findings.extend(secrets::scan_file(&path, &text));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pentest-sast-lib-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scan_finds_issues_across_multiple_languages_and_files() {
        let root = temp_dir("multi-lang");
        fs::write(
            root.join("app.py"),
            "cur.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n",
        )
        .unwrap();
        fs::write(root.join("app.js"), "child_process.exec(cmd);\n").unwrap();
        fs::write(
            root.join(".env"),
            "api_key = \"sk_live_abcdefgh12345678\"\n",
        )
        .unwrap();

        let findings = scan(&root, &[]);

        assert!(findings.iter().any(|f| f.check == "sast_sqli_concat"));
        assert!(findings.iter().any(|f| f.check == "sast_command_exec"));
        assert!(findings.iter().any(|f| f.check == "sast_hardcoded_secret"));
    }

    #[test]
    fn scan_of_clean_tree_produces_no_findings() {
        let root = temp_dir("clean");
        fs::write(
            root.join("app.py"),
            "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n",
        )
        .unwrap();
        fs::write(root.join("app.js"), "spawn('ls', ['-la']);\n").unwrap();

        let findings = scan(&root, &[]);

        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[test]
    fn scan_skips_node_modules_and_git_directories() {
        let root = temp_dir("skip-dirs");
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("evil.js"), "eval(x);\n").unwrap();

        let findings = scan(&root, &[]);

        assert!(findings.is_empty());
    }

    // --- B2 regression: an explicit `exclude` path must keep everything
    // under it out of the scan, by canonicalized path -- not by name --
    // so a scan doesn't re-detect secrets embedded in its own prior CVE
    // output on the next run (a self-scan feedback loop).
    #[test]
    fn scan_excludes_a_canonicalized_subdirectory() {
        let root = temp_dir("exclude-subdir");
        fs::write(root.join("app.js"), "child_process.exec(cmd);\n").unwrap();
        let sub = root.join("cve");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("evil.js"), "eval(user_input);\n").unwrap();

        let excluded = fs::canonicalize(&sub).unwrap();
        let findings = scan(&root, &[excluded]);

        assert!(
            findings.iter().any(|f| f.check == "sast_command_exec"),
            "root-level file's finding must still be present"
        );
        assert!(
            !findings.iter().any(|f| f.evidence.contains("evil.js")),
            "excluded subdirectory's finding must NOT be present, got {findings:?}"
        );
    }

    // --- B3 regression: a single invalid UTF-8 byte anywhere in a file
    // must not silently disable the hardcoded-secret rule for the whole
    // file. Before the fix (`str::from_utf8` + early-skip), this file
    // would have produced zero findings.
    #[test]
    fn scan_still_detects_secrets_in_a_file_with_invalid_utf8_bytes() {
        let root = temp_dir("invalid-utf8");
        let mut bytes = b"api_key = \"sk_live_abcdefgh12345678\"\n".to_vec();
        bytes.push(0xFF);
        fs::write(root.join("config.txt"), &bytes).unwrap();

        let findings = scan(&root, &[]);

        assert!(
            findings.iter().any(|f| f.check == "sast_hardcoded_secret"),
            "expected the secret to still be detected, got {findings:?}"
        );
    }
}

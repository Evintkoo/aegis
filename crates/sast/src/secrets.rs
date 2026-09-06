//! Hardcoded-secret rule (CWE-798). Deliberately regex-based, not a
//! tree-sitter query -- secrets show up in config/env/yaml files that
//! have no grammar at all, and the signal is lexical (a suspicious key
//! name next to a long opaque string), not structural. Runs against
//! every walked file's raw bytes regardless of recognized language.

use pentest_core::{Finding, Severity};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

pub const CHECK: &str = "sast_hardcoded_secret";
const CWE: &str = "CWE-798";
const TITLE: &str = "Hardcoded secret";
const REMEDIATION: &str = "Remove the secret from source, rotate it, and load it from an environment variable or secrets manager instead.";

// Deliberately no leading `\b` before the key-name alternation: a real
// secret is just as often named `DATABASE_PASSWORD` or `APP_API_KEY`
// as bare `password`, and `\b` cannot match between the `_` and `P` in
// `DATABASE_PASSWORD` (both are word characters) -- confirmed by a real
// failing fixture during prototyping (`DATABASE_PASSWORD = "..."` went
// undetected with the naive `\b(...)\b` version). The immediately-following
// `\s*[:=]\s*["']` already bounds false positives on the right (e.g.
// `password_hint = "..."` doesn't match: `_hint` sits between the key word
// and `=`, so the required "whitespace then assignment" gap isn't there).
static ASSIGNED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{12,})["']"#).unwrap()
});
static AWS_ACCESS_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());
static PRIVATE_KEY_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap());

/// Values that look like secrets lexically but are common non-secret
/// placeholders (env-var lookups, empty strings, obvious samples) --
/// keeps the assigned-secret pattern from firing on `os.environ["..."]`
/// idioms that happen to contain a quoted key-name string.
fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.is_empty()
        || lower.starts_with("$")
        || lower.starts_with("process.env")
        || lower.starts_with("env.")
        || lower.contains("your_")
        || lower.contains("changeme")
        || lower.contains("xxxxxxxx")
        || lower.chars().all(|c| c == '0' || c == 'x')
}

pub fn scan_file(path: &Path, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (ix, line) in source.lines().enumerate() {
        let lineno = ix + 1;

        if let Some(caps) = ASSIGNED_SECRET.captures(line) {
            let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if !looks_like_placeholder(value) {
                findings.push(finding(path, lineno, line));
            }
        }
        if AWS_ACCESS_KEY.is_match(line) {
            findings.push(finding(path, lineno, line));
        }
        if PRIVATE_KEY_HEADER.is_match(line) {
            findings.push(finding(path, lineno, line));
        }
    }
    findings
}

fn finding(path: &Path, lineno: usize, line: &str) -> Finding {
    let snippet: String = line.trim().chars().take(120).collect();
    let mut f = Finding::new(CHECK, Severity::Critical, TITLE, format!("{CWE} [{CHECK}]"))
        .with_evidence(format!("{}:{lineno}: {snippet}", path.display()));
    f.remediation = REMEDIATION.to_string();
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_hardcoded_password_assignment() {
        let src = "password = \"SuperSecretValue123\"\n";
        let findings = scan_file(Path::new("config.py"), src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_key_name_embedded_in_a_longer_constant_case_identifier() {
        let src = "DATABASE_PASSWORD = \"pr0duct10n-db-pass-2026\"\n";
        let findings = scan_file(Path::new("settings.py"), src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_env_var_lookup() {
        let src = "api_key = os.environ[\"API_KEY\"]\n";
        let findings = scan_file(Path::new("config.py"), src);
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_empty_or_placeholder_value() {
        let src = "SECRET_KEY = \"\"\ntoken: \"changeme_replace_me\"\n";
        let findings = scan_file(Path::new("config.py"), src);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_aws_access_key_id() {
        let src = "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n";
        let findings = scan_file(Path::new(".env"), src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_private_key_header() {
        let src = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n";
        let findings = scan_file(Path::new("id_rsa"), src);
        assert_eq!(findings.len(), 1);
    }
}

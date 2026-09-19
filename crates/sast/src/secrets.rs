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
static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());
static PRIVATE_KEY_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap());
static GITHUB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b").unwrap());
static SLACK_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap());
static GOOGLE_API_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap());
static STRIPE_LIVE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b").unwrap());
static SENDGRID_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b").unwrap());
static JWT_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\b").unwrap()
});
static CREDENTIALED_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://([^\s:/'"]+):([^\s@/'"]+)@"#,
    )
    .unwrap()
});

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
                findings.push(finding(path, lineno, line, TITLE, Severity::Critical));
            }
        }
        if AWS_ACCESS_KEY.is_match(line) {
            findings.push(finding(path, lineno, line, TITLE, Severity::Critical));
        }
        if PRIVATE_KEY_HEADER.is_match(line) {
            findings.push(finding(path, lineno, line, TITLE, Severity::Critical));
        }
        if GITHUB_TOKEN.is_match(line) {
            findings.push(finding(
                path,
                lineno,
                line,
                "Hardcoded GitHub token",
                Severity::High,
            ));
        }
        if SLACK_TOKEN.is_match(line) {
            findings.push(finding(
                path,
                lineno,
                line,
                "Hardcoded Slack token",
                Severity::High,
            ));
        }
        if GOOGLE_API_KEY.is_match(line) {
            findings.push(finding(
                path,
                lineno,
                line,
                "Hardcoded Google API key",
                Severity::High,
            ));
        }
        // Live Stripe keys are random base62; a run with no digit at all is
        // an alphabet-sequence sample (e.g. docs/test fixtures), not a key.
        if let Some(m) = STRIPE_LIVE_KEY.find(line) {
            if m.as_str().chars().any(|c| c.is_ascii_digit()) {
                findings.push(finding(
                    path,
                    lineno,
                    line,
                    "Hardcoded Stripe live key",
                    Severity::High,
                ));
            }
        }
        if SENDGRID_KEY.is_match(line) {
            findings.push(finding(
                path,
                lineno,
                line,
                "Hardcoded SendGrid API key",
                Severity::High,
            ));
        }
        if JWT_LITERAL.is_match(line) {
            findings.push(finding(
                path,
                lineno,
                line,
                "Hardcoded JWT literal",
                Severity::Medium,
            ));
        }
        if let Some(caps) = CREDENTIALED_URL.captures(line) {
            let user = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let pass = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let pair = format!("{user}:{pass}");
            let generic_pair = matches!(
                pair.to_lowercase().as_str(),
                "user:pass" | "user:password" | "username:password" | "xxx:yyy"
            );
            if !generic_pair
                && !looks_like_placeholder(user)
                && !looks_like_placeholder(pass)
                && !looks_like_placeholder(&pair)
            {
                findings.push(finding(
                    path,
                    lineno,
                    line,
                    "Hardcoded credentialed connection string",
                    Severity::High,
                ));
            }
        }
    }
    findings
}

fn finding(path: &Path, lineno: usize, line: &str, title: &str, severity: Severity) -> Finding {
    let snippet: String = line.trim().chars().take(120).collect();
    let mut f = Finding::new(CHECK, severity, title, format!("{CWE} [{CHECK}]"))
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

    #[test]
    fn flags_github_token() {
        let src = "github = \"ghp_Rv2Kq8XzW1nY4tUe6iO0pA3sD7fG5hJ9lBvN\"\n";
        let findings = scan_file(Path::new("ci.yml"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_slack_token() {
        let src = "slack = \"xoxb-123456789012-abcdefghij\"\n";
        let findings = scan_file(Path::new("config.toml"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_google_api_key() {
        let src = "google_key = \"AIzaSyD1234567890abcdefghijklmnopqrstuv\"\n";
        let findings = scan_file(Path::new("settings.py"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_stripe_live_key() {
        let body = "Kl2vX9wQpR7sT4uY8bZ3mN6d";
        let src = format!("stripe = \"sk_live_{body}\"\n");
        let findings = scan_file(Path::new("config.py"), &src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn does_not_flag_letter_only_stripe_sample() {
        let src = "stripe_test = \"sk_live_abcdefghijklmnopqrstuvwx\"\n";
        let findings = scan_file(Path::new("config.py"), src);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_sendgrid_key() {
        let src = "sendgrid = \"SG.aBcDeFgHiJkLmNoP.1234567890abcdefGHIJKLMN\"\n";
        let findings = scan_file(Path::new(".env"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_jwt_literal() {
        let src = "auth_header = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c\"\n";
        let findings = scan_file(Path::new("handler.js"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_credentialed_connection_string() {
        let src = "mongodb://ops_user:Sup3rS3cret@cluster0.abc12.mongodb.net/db\n";
        let findings = scan_file(Path::new("docker-compose.yml"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn does_not_flag_placeholder_connection_strings() {
        let src = concat!(
            "mongodb://USER:PASSWORD@localhost:27017\n",
            "postgres://user:password@db.internal/prod\n",
            "redis://xxx:yyy@example.com\n",
            "mysql://$USER:$PASS@host\n",
        );
        let findings = scan_file(Path::new("docker-compose.yml"), src);
        assert!(findings.is_empty());
    }
}

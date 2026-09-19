//! Standards mapping registry: every check in the toolkit maps to the
//! industry references a professional pentest report cites —
//!
//! - **WSTG** — OWASP Web Security Testing Guide v4.2 test IDs, in the
//!   versioned form the guide itself requests for tooling and reports
//!   (`WSTG-v42-<CATEGORY>-<NN>`, see the WSTG README "How To Reference
//!   WSTG Scenarios"). IDs are taken from the published v4.2 table of
//!   contents, not invented.
//! - **CWE** — weakness taxonomy entry for the weakness class probed.
//! - **CAPEC** — attack-pattern taxonomy entry for the canonical attack
//!   (included only where a single CAPEC pattern is iconic for the check).
//!
//! These refs ride on every finding (`Finding::refs`), in `--list-checks
//! --json`, and in the human check list, so a run's output can be dropped
//! straight into a PTES/NIST SP 800-115-style report and audited against
//! OWASP WSTG coverage.

/// Standards references for one check, or an empty slice for checks that
/// map to no specific test (generic orchestrators like `external`).
pub fn refs_for(check: &str) -> &'static [&'static str] {
    match check {
        // ---- DAST: information gathering / configuration (WSTG 4.1, 4.2)
        "recon" => &[
            "WSTG-v42-INFO-02",
            "WSTG-v42-INFO-08",
            "WSTG-v42-CRYP-01",
            "CWE-200",
        ],
        "content_discovery" => &[
            "WSTG-v42-INFO-03",
            "WSTG-v42-INFO-04",
            "WSTG-v42-CONF-04",
            "WSTG-v42-CONF-05",
            "CWE-538",
        ],
        "files" => &["WSTG-v42-CONF-03", "WSTG-v42-CONF-04", "CWE-538"],
        "api_docs" => &["WSTG-v42-CONF-05", "WSTG-v42-INFO-04", "CWE-538", "CWE-200"],
        "debug_endpoints" => &["WSTG-v42-CONF-02", "WSTG-v42-CONF-05", "CWE-489", "CWE-200"],
        "tls_enum" => &["WSTG-v42-CRYP-01", "CWE-326"],

        // ---- DAST: authentication / authorization (WSTG 4.3–4.5)
        "auth_bruteforce" => &[
            "WSTG-v42-IDENT-04",
            "WSTG-v42-ATHN-03",
            "CWE-204",
            "CWE-307",
        ],
        "idor" => &["WSTG-v42-ATHZ-04", "CWE-639"],
        "traversal" => &["WSTG-v42-ATHZ-01", "CWE-22", "CAPEC-126"],

        // ---- DAST: session management (WSTG 4.6)
        "csrf" => &["WSTG-v42-SESS-05", "CWE-352", "CAPEC-62"],
        "jwt" => &["WSTG-v42-SESS-01", "WSTG-v42-CRYP-04", "CWE-347"],
        "cache_deception" => &["WSTG-v42-SESS-09", "CWE-524"],
        "host_header" => &["WSTG-v42-INPV-17", "CWE-113"],

        // ---- DAST: input validation (WSTG 4.7)
        "sqli" => &["WSTG-v42-INPV-05", "CWE-89", "CAPEC-66"],
        "nosqli" => &["WSTG-v42-INPV-05", "CWE-943"],
        "cmdi" => &["WSTG-v42-INPV-12", "CWE-78", "CAPEC-88"],
        "ssti" => &["WSTG-v42-INPV-18", "CWE-1336", "CAPEC-650"],
        "xxe" => &["WSTG-v42-INPV-07", "CWE-611", "CAPEC-201"],
        "ldap_injection" => &["WSTG-v42-INPV-06", "CWE-90"],
        "xpath_injection" => &["WSTG-v42-INPV-09", "CWE-643"],
        "crlf" => &["WSTG-v42-INPV-15", "CWE-113"],
        "request_smuggling" => &["WSTG-v42-INPV-15", "CWE-436"],
        "hpp" => &["WSTG-v42-INPV-04", "CWE-235"],
        "xss" => &["WSTG-v42-INPV-01", "CWE-79", "CAPEC-63"],
        "ssrf" => &["WSTG-v42-INPV-19", "CWE-918", "CAPEC-664"],
        "blind_oob" => &["WSTG-v42-INPV-19", "WSTG-v42-INPV-02", "CWE-918", "CWE-79"],
        "log4shell" => &["WSTG-v42-INPV-12", "CWE-917", "CAPEC-417"],
        "deserialize" => &["WSTG-v42-INPV-11", "CWE-502"],

        // ---- DAST: error handling / business logic (WSTG 4.8, 4.10)
        "info_disclosure" => &["WSTG-v42-ERRH-01", "WSTG-v42-ERRH-02", "CWE-209", "CWE-200"],
        "business_logic" => &["WSTG-v42-BUSL-01", "CWE-840"],
        "race_condition" => &["WSTG-v42-BUSL-05", "CWE-362"],

        // ---- DAST: client-side (WSTG 4.11)
        "dom_xss" => &["WSTG-v42-CLNT-01", "CWE-79"],
        "redirect" => &["WSTG-v42-CLNT-04", "CWE-601"],
        "cors_advanced" => &["WSTG-v42-CLNT-07", "CWE-942"],
        "clickjacking" => &["WSTG-v42-CLNT-09", "CWE-1021"],

        // ---- DAST: API (WSTG 4.12)
        "graphql" => &["WSTG-v42-APIT-01", "CWE-200"],

        // ---- DAST: misc
        "headers" => &["WSTG-v42-CONF-07", "WSTG-v42-SESS-02", "CWE-693"],
        "method_tampering" => &["WSTG-v42-CONF-06", "WSTG-v42-INPV-03", "CWE-650"],
        "secrets_in_js" => &["WSTG-v42-INFO-05", "CWE-200"],
        "discovery" => &["WSTG-v42-INFO-06"],

        // ---- SAST (same weakness classes, found in source instead)
        "sast_sqli_concat" => &["WSTG-v42-INPV-05", "CWE-89", "CAPEC-66"],
        "sast_command_exec" => &["WSTG-v42-INPV-12", "CWE-78", "CAPEC-88"],
        "sast_unsafe_deserialize" => &["WSTG-v42-INPV-11", "CWE-502"],
        "sast_weak_crypto" => &["WSTG-v42-CRYP-04", "CWE-327"],
        "sast_path_traversal" => &["WSTG-v42-ATHZ-01", "CWE-22"],
        "sast_ssrf" => &["WSTG-v42-INPV-19", "CWE-918"],
        "sast_open_redirect" => &["WSTG-v42-CLNT-04", "CWE-601"],
        "sast_xss_sink" => &["WSTG-v42-INPV-01", "CWE-79"],
        "sast_tls_verify_disabled" => &["WSTG-v42-CRYP-01", "CWE-295"],
        "sast_xpath_injection" => &["WSTG-v42-INPV-09", "CWE-643"],
        "sast_ldap_injection" => &["WSTG-v42-INPV-06", "CWE-90"],
        "sast_weak_random" => &["WSTG-v42-CRYP-04", "CWE-338"],
        "hardcoded_secrets" => &["WSTG-v42-INFO-05", "CWE-798"],

        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A representative sample of the DAST registry. `pentest_dast` cannot
    // be a dependency of `pentest-core` (dast depends on core), so the
    // FULL registration audit lives in tests/cli.rs, which can see both.
    const DAST_SAMPLE: &[&str] = &[
        "recon",
        "headers",
        "files",
        "content_discovery",
        "sqli",
        "nosqli",
        "xss",
        "dom_xss",
        "csrf",
        "idor",
        "traversal",
        "xxe",
        "ssrf",
        "ssti",
        "cmdi",
        "graphql",
        "jwt",
        "deserialize",
        "business_logic",
        "race_condition",
        "request_smuggling",
        "hpp",
        "log4shell",
        "tls_enum",
        "api_docs",
        "debug_endpoints",
    ];

    #[test]
    fn dast_sample_checks_have_wstg_refs() {
        for c in DAST_SAMPLE {
            let refs = refs_for(c);
            assert!(
                !refs.is_empty(),
                "check '{c}' has no standards refs; add a mapping in standards.rs"
            );
            assert!(
                refs.iter().any(|r| r.starts_with("WSTG-v42-")),
                "check '{c}' refs lack a WSTG id: {refs:?}"
            );
        }
    }

    #[test]
    fn sast_rules_have_refs() {
        for c in [
            "sast_sqli_concat",
            "sast_command_exec",
            "sast_unsafe_deserialize",
            "sast_weak_crypto",
            "sast_path_traversal",
            "sast_ssrf",
            "sast_open_redirect",
            "sast_xss_sink",
            "sast_tls_verify_disabled",
            "sast_xpath_injection",
            "sast_ldap_injection",
            "sast_weak_random",
            "hardcoded_secrets",
        ] {
            assert!(!refs_for(c).is_empty(), "sast rule '{c}' has no refs");
        }
    }

    #[test]
    fn generic_or_unknown_checks_map_to_empty() {
        // `external` wraps third-party tools with their own taxonomies and
        // `cve-match` records a real CVE — neither needs a fixed ref set.
        assert!(refs_for("external").is_empty());
        assert!(refs_for("cve-match").is_empty());
        assert!(refs_for("nonexistent-check").is_empty());
    }

    #[test]
    fn wstg_ids_are_well_formed() {
        for c in DAST_SAMPLE {
            for r in refs_for(c) {
                if let Some(id) = r.strip_prefix("WSTG-v42-") {
                    let mut parts = id.split('-');
                    let cat = parts.next().unwrap_or("");
                    let num = parts.next().unwrap_or("");
                    assert_eq!(parts.next(), None, "malformed WSTG ref {r}");
                    assert_eq!(cat.len(), 4, "WSTG category must be 4 chars: {r}");
                    assert_eq!(num.len(), 2, "WSTG number must be zero-padded 2: {r}");
                    assert!(
                        num.bytes().all(|b| b.is_ascii_digit()),
                        "WSTG number must be numeric: {r}"
                    );
                }
            }
        }
    }
}

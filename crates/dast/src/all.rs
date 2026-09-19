use crate::checks::{
    api_docs, auth_bruteforce, blind_oob, business_logic, cache_deception, clickjacking, cmdi,
    content_discovery, cors_advanced, crlf, csrf, debug_endpoints, deserialize, dom_xss, external,
    files, graphql, headers, host_header, hpp, idor, info_disclosure, jwt, ldap_injection,
    log4shell, method_tampering, nosqli, race_condition, recon, redirect, request_smuggling,
    secrets_in_js, sqli, ssrf, ssti, tls_enum, traversal, xpath_injection, xss, xxe,
};
use crate::registry::CheckEntry;

/// Site-level checks: run once against the target's base URL, no
/// parameter required. Ordered to match `checks/__init__.py`'s own
/// category grouping (recon/discovery -> non-param injection (xxe) ->
/// logic/config -> disclosure -> opt-in), even though Python interleaves
/// these with the PARAM checks in one combined list -- `SITE` then
/// `PARAM` (see `ALL` below) is this port's own, simpler convention,
/// unchanged from Plan 3.
pub const SITE: &[CheckEntry] = &[
    CheckEntry {
        name: recon::NAME,
        run: recon::run,
    },
    CheckEntry {
        name: tls_enum::NAME,
        run: tls_enum::run,
    },
    CheckEntry {
        name: api_docs::NAME,
        run: api_docs::run,
    },
    CheckEntry {
        name: debug_endpoints::NAME,
        run: debug_endpoints::run,
    },
    CheckEntry {
        name: headers::NAME,
        run: headers::run,
    },
    CheckEntry {
        name: content_discovery::NAME,
        run: content_discovery::run,
    },
    CheckEntry {
        name: files::NAME,
        run: files::run,
    },
    CheckEntry {
        name: log4shell::NAME,
        run: log4shell::run,
    },
    CheckEntry {
        name: xxe::NAME,
        run: xxe::run,
    },
    CheckEntry {
        name: ssrf::NAME,
        run: ssrf::run,
    },
    CheckEntry {
        name: redirect::NAME,
        run: redirect::run,
    },
    CheckEntry {
        name: host_header::NAME,
        run: host_header::run,
    },
    CheckEntry {
        name: csrf::NAME,
        run: csrf::run,
    },
    CheckEntry {
        name: cors_advanced::NAME,
        run: cors_advanced::run,
    },
    CheckEntry {
        name: clickjacking::NAME,
        run: clickjacking::run,
    },
    CheckEntry {
        name: method_tampering::NAME,
        run: method_tampering::run,
    },
    CheckEntry {
        name: cache_deception::NAME,
        run: cache_deception::run,
    },
    CheckEntry {
        name: graphql::NAME,
        run: graphql::run,
    },
    CheckEntry {
        name: jwt::NAME,
        run: jwt::run,
    },
    CheckEntry {
        name: info_disclosure::NAME,
        run: info_disclosure::run,
    },
    CheckEntry {
        name: secrets_in_js::NAME,
        run: secrets_in_js::run,
    },
    CheckEntry {
        name: dom_xss::NAME,
        run: dom_xss::run,
    },
    CheckEntry {
        name: auth_bruteforce::NAME,
        run: auth_bruteforce::run,
    },
    CheckEntry {
        name: blind_oob::NAME,
        run: blind_oob::run,
    },
    CheckEntry {
        name: race_condition::NAME,
        run: race_condition::run,
    },
    CheckEntry {
        name: request_smuggling::NAME,
        run: request_smuggling::run,
    },
    CheckEntry {
        name: external::NAME,
        run: external::run,
    },
];

/// Parameter-fuzzing checks: need a `param` (from `-p`, or discovered
/// crawling/mining) to inject into. The first ten match `run_all.py`'s
/// actual `PARAM_CHECKS` set exactly (verified against the source, not
/// assumed) -- e.g. `idor` IS a param check by that set even though
/// Python's own `checks/__init__.py` declares it far later, interleaved
/// with the disclosure checks; `xxe` is NOT, despite living among the
/// injection checks there, which is why it's ported into `SITE` above.
/// The last two (`deserialize`, `business_logic`) are post-port
/// extensions the Python toolkit never had, pinned by
/// `param_checks_extend_the_python_parity_set` below.
pub const PARAM: &[CheckEntry] = &[
    CheckEntry {
        name: sqli::NAME,
        run: sqli::run,
    },
    CheckEntry {
        name: nosqli::NAME,
        run: nosqli::run,
    },
    CheckEntry {
        name: cmdi::NAME,
        run: cmdi::run,
    },
    CheckEntry {
        name: ssti::NAME,
        run: ssti::run,
    },
    CheckEntry {
        name: traversal::NAME,
        run: traversal::run,
    },
    CheckEntry {
        name: crlf::NAME,
        run: crlf::run,
    },
    CheckEntry {
        name: xss::NAME,
        run: xss::run,
    },
    CheckEntry {
        name: ldap_injection::NAME,
        run: ldap_injection::run,
    },
    CheckEntry {
        name: xpath_injection::NAME,
        run: xpath_injection::run,
    },
    CheckEntry {
        name: idor::NAME,
        run: idor::run,
    },
    CheckEntry {
        name: hpp::NAME,
        run: hpp::run,
    },
    CheckEntry {
        name: deserialize::NAME,
        run: deserialize::run,
    },
    CheckEntry {
        name: business_logic::NAME,
        run: business_logic::run,
    },
];

/// Every check, `SITE` then `PARAM` -- for `--list-checks` and for
/// `--only`/`--skip` filtering, which apply across both categories at
/// once. Kept as its own literal (rather than concatenating `SITE` and
/// `PARAM`) since Rust has no const-friendly slice concatenation.
pub const ALL: &[CheckEntry] = &[
    CheckEntry {
        name: recon::NAME,
        run: recon::run,
    },
    CheckEntry {
        name: tls_enum::NAME,
        run: tls_enum::run,
    },
    CheckEntry {
        name: api_docs::NAME,
        run: api_docs::run,
    },
    CheckEntry {
        name: debug_endpoints::NAME,
        run: debug_endpoints::run,
    },
    CheckEntry {
        name: headers::NAME,
        run: headers::run,
    },
    CheckEntry {
        name: content_discovery::NAME,
        run: content_discovery::run,
    },
    CheckEntry {
        name: files::NAME,
        run: files::run,
    },
    CheckEntry {
        name: log4shell::NAME,
        run: log4shell::run,
    },
    CheckEntry {
        name: xxe::NAME,
        run: xxe::run,
    },
    CheckEntry {
        name: ssrf::NAME,
        run: ssrf::run,
    },
    CheckEntry {
        name: redirect::NAME,
        run: redirect::run,
    },
    CheckEntry {
        name: host_header::NAME,
        run: host_header::run,
    },
    CheckEntry {
        name: csrf::NAME,
        run: csrf::run,
    },
    CheckEntry {
        name: cors_advanced::NAME,
        run: cors_advanced::run,
    },
    CheckEntry {
        name: clickjacking::NAME,
        run: clickjacking::run,
    },
    CheckEntry {
        name: method_tampering::NAME,
        run: method_tampering::run,
    },
    CheckEntry {
        name: cache_deception::NAME,
        run: cache_deception::run,
    },
    CheckEntry {
        name: graphql::NAME,
        run: graphql::run,
    },
    CheckEntry {
        name: jwt::NAME,
        run: jwt::run,
    },
    CheckEntry {
        name: info_disclosure::NAME,
        run: info_disclosure::run,
    },
    CheckEntry {
        name: secrets_in_js::NAME,
        run: secrets_in_js::run,
    },
    CheckEntry {
        name: dom_xss::NAME,
        run: dom_xss::run,
    },
    CheckEntry {
        name: auth_bruteforce::NAME,
        run: auth_bruteforce::run,
    },
    CheckEntry {
        name: blind_oob::NAME,
        run: blind_oob::run,
    },
    CheckEntry {
        name: race_condition::NAME,
        run: race_condition::run,
    },
    CheckEntry {
        name: request_smuggling::NAME,
        run: request_smuggling::run,
    },
    CheckEntry {
        name: external::NAME,
        run: external::run,
    },
    CheckEntry {
        name: sqli::NAME,
        run: sqli::run,
    },
    CheckEntry {
        name: nosqli::NAME,
        run: nosqli::run,
    },
    CheckEntry {
        name: cmdi::NAME,
        run: cmdi::run,
    },
    CheckEntry {
        name: ssti::NAME,
        run: ssti::run,
    },
    CheckEntry {
        name: traversal::NAME,
        run: traversal::run,
    },
    CheckEntry {
        name: crlf::NAME,
        run: crlf::run,
    },
    CheckEntry {
        name: xss::NAME,
        run: xss::run,
    },
    CheckEntry {
        name: ldap_injection::NAME,
        run: ldap_injection::run,
    },
    CheckEntry {
        name: xpath_injection::NAME,
        run: xpath_injection::run,
    },
    CheckEntry {
        name: idor::NAME,
        run: idor::run,
    },
    CheckEntry {
        name: hpp::NAME,
        run: hpp::run,
    },
    CheckEntry {
        name: deserialize::NAME,
        run: deserialize::run,
    },
    CheckEntry {
        name: business_logic::NAME,
        run: business_logic::run,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_site_then_param_checks_in_order() {
        let names: Vec<&str> = ALL.iter().map(|c| c.name).collect();
        let mut expected: Vec<&str> = SITE.iter().map(|c| c.name).collect();
        expected.extend(PARAM.iter().map(|c| c.name));
        assert_eq!(names, expected);
        assert_eq!(names.len(), 40);
    }

    #[test]
    fn site_and_param_together_cover_all_with_no_overlap() {
        let site_names: std::collections::HashSet<&str> = SITE.iter().map(|c| c.name).collect();
        let param_names: std::collections::HashSet<&str> = PARAM.iter().map(|c| c.name).collect();
        assert!(site_names.is_disjoint(&param_names));
        assert_eq!(site_names.len() + param_names.len(), ALL.len());
    }

    #[test]
    fn param_checks_carry_the_python_parity_subset() {
        // Ground truth from run_all.py's PARAM_CHECKS, not the design
        // spec's prose grouping. `PARAM` must still contain every one of
        // these -- the post-port extensions (see below) add to the set,
        // they do not replace it.
        let python_parity: std::collections::HashSet<&str> = [
            "sqli",
            "nosqli",
            "cmdi",
            "ssti",
            "traversal",
            "crlf",
            "xss",
            "ldap_injection",
            "xpath_injection",
            "idor",
        ]
        .into_iter()
        .collect();
        let actual: std::collections::HashSet<&str> = PARAM.iter().map(|c| c.name).collect();
        assert!(
            python_parity.is_subset(&actual),
            "PARAM lost a Python-parity check: {:?}",
            python_parity.difference(&actual)
        );
    }

    #[test]
    fn param_checks_extend_the_python_parity_set() {
        // The three PARAM checks the Python toolkit never had. Pinned
        // here so a rename or accidental removal of any is caught.
        let actual: std::collections::HashSet<&str> = PARAM.iter().map(|c| c.name).collect();
        for name in ["deserialize", "business_logic", "hpp"] {
            assert!(
                actual.contains(name),
                "missing post-port PARAM check '{name}'"
            );
        }
    }

    #[test]
    fn opt_in_checks_stay_registered_in_all() {
        // The opt-in (flag-gated) checks are no-ops without their flag,
        // which makes a dropped registration invisible in normal runs.
        // Pin them by name so they can't silently fall out of ALL.
        let names: std::collections::HashSet<&str> = ALL.iter().map(|c| c.name).collect();
        for name in [
            "race_condition",
            "request_smuggling",
            "tls_enum",
            "blind_oob",
            "auth_bruteforce",
            "external",
        ] {
            assert!(names.contains(name), "missing opt-in check '{name}'");
        }
    }
}

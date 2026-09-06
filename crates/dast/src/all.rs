use crate::checks::{
    auth_bruteforce, blind_oob, cache_deception, clickjacking, cmdi, content_discovery, cors_advanced, crlf, csrf, external, files, graphql, headers, host_header, idor,
    info_disclosure, jwt, ldap_injection, method_tampering, nosqli, recon, redirect, secrets_in_js, sqli, ssrf, ssti, traversal, xpath_injection, xss, xxe,
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
    CheckEntry { name: recon::NAME, run: recon::run },
    CheckEntry { name: headers::NAME, run: headers::run },
    CheckEntry { name: content_discovery::NAME, run: content_discovery::run },
    CheckEntry { name: files::NAME, run: files::run },
    CheckEntry { name: xxe::NAME, run: xxe::run },
    CheckEntry { name: ssrf::NAME, run: ssrf::run },
    CheckEntry { name: redirect::NAME, run: redirect::run },
    CheckEntry { name: host_header::NAME, run: host_header::run },
    CheckEntry { name: csrf::NAME, run: csrf::run },
    CheckEntry { name: cors_advanced::NAME, run: cors_advanced::run },
    CheckEntry { name: clickjacking::NAME, run: clickjacking::run },
    CheckEntry { name: method_tampering::NAME, run: method_tampering::run },
    CheckEntry { name: cache_deception::NAME, run: cache_deception::run },
    CheckEntry { name: graphql::NAME, run: graphql::run },
    CheckEntry { name: jwt::NAME, run: jwt::run },
    CheckEntry { name: info_disclosure::NAME, run: info_disclosure::run },
    CheckEntry { name: secrets_in_js::NAME, run: secrets_in_js::run },
    CheckEntry { name: auth_bruteforce::NAME, run: auth_bruteforce::run },
    CheckEntry { name: blind_oob::NAME, run: blind_oob::run },
    CheckEntry { name: external::NAME, run: external::run },
];

/// Parameter-fuzzing checks: need a `param` (from `-p`, or discovered
/// crawling/mining) to inject into. Matches `run_all.py`'s actual
/// `PARAM_CHECKS` set exactly (verified against the source, not assumed)
/// -- e.g. `idor` IS a param check by that set even though Python's own
/// `checks/__init__.py` declares it far later, interleaved with the
/// disclosure checks; `xxe` is NOT, despite living among the injection
/// checks there, which is why it's ported into `SITE` above.
pub const PARAM: &[CheckEntry] = &[
    CheckEntry { name: sqli::NAME, run: sqli::run },
    CheckEntry { name: nosqli::NAME, run: nosqli::run },
    CheckEntry { name: cmdi::NAME, run: cmdi::run },
    CheckEntry { name: ssti::NAME, run: ssti::run },
    CheckEntry { name: traversal::NAME, run: traversal::run },
    CheckEntry { name: crlf::NAME, run: crlf::run },
    CheckEntry { name: xss::NAME, run: xss::run },
    CheckEntry { name: ldap_injection::NAME, run: ldap_injection::run },
    CheckEntry { name: xpath_injection::NAME, run: xpath_injection::run },
    CheckEntry { name: idor::NAME, run: idor::run },
];

/// Every check, `SITE` then `PARAM` -- for `--list-checks` and for
/// `--only`/`--skip` filtering, which apply across both categories at
/// once. Kept as its own literal (rather than concatenating `SITE` and
/// `PARAM`) since Rust has no const-friendly slice concatenation.
pub const ALL: &[CheckEntry] = &[
    CheckEntry { name: recon::NAME, run: recon::run },
    CheckEntry { name: headers::NAME, run: headers::run },
    CheckEntry { name: content_discovery::NAME, run: content_discovery::run },
    CheckEntry { name: files::NAME, run: files::run },
    CheckEntry { name: xxe::NAME, run: xxe::run },
    CheckEntry { name: ssrf::NAME, run: ssrf::run },
    CheckEntry { name: redirect::NAME, run: redirect::run },
    CheckEntry { name: host_header::NAME, run: host_header::run },
    CheckEntry { name: csrf::NAME, run: csrf::run },
    CheckEntry { name: cors_advanced::NAME, run: cors_advanced::run },
    CheckEntry { name: clickjacking::NAME, run: clickjacking::run },
    CheckEntry { name: method_tampering::NAME, run: method_tampering::run },
    CheckEntry { name: cache_deception::NAME, run: cache_deception::run },
    CheckEntry { name: graphql::NAME, run: graphql::run },
    CheckEntry { name: jwt::NAME, run: jwt::run },
    CheckEntry { name: info_disclosure::NAME, run: info_disclosure::run },
    CheckEntry { name: secrets_in_js::NAME, run: secrets_in_js::run },
    CheckEntry { name: auth_bruteforce::NAME, run: auth_bruteforce::run },
    CheckEntry { name: blind_oob::NAME, run: blind_oob::run },
    CheckEntry { name: external::NAME, run: external::run },
    CheckEntry { name: sqli::NAME, run: sqli::run },
    CheckEntry { name: nosqli::NAME, run: nosqli::run },
    CheckEntry { name: cmdi::NAME, run: cmdi::run },
    CheckEntry { name: ssti::NAME, run: ssti::run },
    CheckEntry { name: traversal::NAME, run: traversal::run },
    CheckEntry { name: crlf::NAME, run: crlf::run },
    CheckEntry { name: xss::NAME, run: xss::run },
    CheckEntry { name: ldap_injection::NAME, run: ldap_injection::run },
    CheckEntry { name: xpath_injection::NAME, run: xpath_injection::run },
    CheckEntry { name: idor::NAME, run: idor::run },
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
        assert_eq!(names.len(), 30);
    }

    #[test]
    fn site_and_param_together_cover_all_with_no_overlap() {
        let site_names: std::collections::HashSet<&str> = SITE.iter().map(|c| c.name).collect();
        let param_names: std::collections::HashSet<&str> = PARAM.iter().map(|c| c.name).collect();
        assert!(site_names.is_disjoint(&param_names));
        assert_eq!(site_names.len() + param_names.len(), ALL.len());
    }

    #[test]
    fn matches_run_all_pys_actual_param_checks_set() {
        // Ground truth from run_all.py's PARAM_CHECKS, not the design
        // spec's prose grouping.
        let expected: std::collections::HashSet<&str> =
            ["sqli", "nosqli", "cmdi", "ssti", "traversal", "crlf", "xss", "ldap_injection", "xpath_injection", "idor"].into_iter().collect();
        let actual: std::collections::HashSet<&str> = PARAM.iter().map(|c| c.name).collect();
        assert_eq!(actual, expected);
    }
}

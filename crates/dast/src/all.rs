use crate::checks::{cmdi, content_discovery, crlf, files, headers, idor, ldap_injection, nosqli, recon, sqli, ssti, traversal, xpath_injection, xss};
use crate::registry::CheckEntry;

/// Site-level checks: run once against the target's base URL, no
/// parameter required.
pub const SITE: &[CheckEntry] = &[
    CheckEntry { name: recon::NAME, run: recon::run },
    CheckEntry { name: headers::NAME, run: headers::run },
    CheckEntry { name: content_discovery::NAME, run: content_discovery::run },
    CheckEntry { name: files::NAME, run: files::run },
];

/// Parameter-fuzzing checks: need a `param` (from `-p`, or discovered
/// crawling/mining) to inject into.
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
        assert_eq!(
            names,
            vec![
                "recon", "headers", "content_discovery", "files", "sqli", "nosqli", "cmdi", "ssti", "traversal",
                "crlf", "xss", "ldap_injection", "xpath_injection", "idor",
            ]
        );
    }

    #[test]
    fn site_and_param_together_cover_all_with_no_overlap() {
        let site_names: std::collections::HashSet<&str> = SITE.iter().map(|c| c.name).collect();
        let param_names: std::collections::HashSet<&str> = PARAM.iter().map(|c| c.name).collect();
        assert!(site_names.is_disjoint(&param_names));
        assert_eq!(site_names.len() + param_names.len(), ALL.len());
    }
}

use crate::checks::{content_discovery, files, headers, recon};
use crate::registry::CheckEntry;

pub const ALL: &[CheckEntry] = &[
    CheckEntry { name: recon::NAME, run: recon::run },
    CheckEntry { name: headers::NAME, run: headers::run },
    CheckEntry { name: content_discovery::NAME, run: content_discovery::run },
    CheckEntry { name: files::NAME, run: files::run },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_the_four_site_checks_in_execution_order() {
        let names: Vec<&str> = ALL.iter().map(|c| c.name).collect();
        assert_eq!(names, vec!["recon", "headers", "content_discovery", "files"]);
    }
}

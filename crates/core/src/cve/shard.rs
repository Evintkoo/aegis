use std::path::{Path, PathBuf};

pub fn thousands_bucket(numeric_id: u64) -> String {
    format!("{}xxx", numeric_id / 1000)
}

pub fn record_path(base_dir: &Path, year: u32, numeric_id: u64, id_str: &str) -> PathBuf {
    base_dir
        .join(year.to_string())
        .join(thousands_bucket(numeric_id))
        .join(format!("{id_str}.json"))
}

/// Parses a real CVE ID (`CVE-YYYY-NNNN...`) into its `(year, numeric_id)`
/// parts, the inputs `record_path` needs to compute the shard directory a
/// fetched real CVE record belongs under. Returns `None` for anything that
/// doesn't match the exact `CVE-<4 digits>-<digits>` shape -- callers treat
/// a non-matching ID (a native OSV/GHSA-only ID with no CVE alias) as a
/// distinct case, not an error.
pub fn parse_cve_id(id: &str) -> Option<(u32, u64)> {
    let rest = id.strip_prefix("CVE-")?;
    let (year_str, num_str) = rest.split_once('-')?;
    if year_str.len() != 4 || !year_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year = year_str.parse().ok()?;
    let numeric_id = num_str.parse().ok()?;
    Some((year, numeric_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_boundaries_match_the_live_cvelistv5_convention() {
        assert_eq!(thousands_bucket(1), "0xxx");
        assert_eq!(thousands_bucket(999), "0xxx");
        assert_eq!(thousands_bucket(1000), "1xxx");
        assert_eq!(thousands_bucket(12345), "12xxx");
        // Verified live against CVE-2021-44228 (Log4Shell) -> cves/2021/44xxx/
        assert_eq!(thousands_bucket(44228), "44xxx");
    }

    #[test]
    fn record_path_matches_the_documented_shape() {
        let path = record_path(Path::new("cve"), 2021, 44228, "CVE-2021-44228");
        assert_eq!(path, PathBuf::from("cve/2021/44xxx/CVE-2021-44228.json"));
    }

    #[test]
    fn parse_cve_id_extracts_year_and_numeric_id() {
        assert_eq!(parse_cve_id("CVE-2021-44228"), Some((2021, 44228)));
        assert_eq!(parse_cve_id("CVE-2026-1"), Some((2026, 1)));
        assert_eq!(parse_cve_id("CVE-1999-0001"), Some((1999, 1)));
    }

    #[test]
    fn parse_cve_id_rejects_non_cve_shapes() {
        assert_eq!(parse_cve_id("GHSA-r9p9-mrjm-926w"), None);
        assert_eq!(parse_cve_id("CVE-21-44228"), None); // year must be 4 digits
        assert_eq!(parse_cve_id("CVE-2021-"), None); // missing numeric part
        assert_eq!(parse_cve_id("CVE-2021-abc"), None); // non-numeric id
        assert_eq!(parse_cve_id("not-a-cve-id"), None);
    }
}

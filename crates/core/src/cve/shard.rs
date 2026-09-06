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
}

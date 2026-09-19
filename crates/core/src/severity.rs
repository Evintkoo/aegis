use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label_upper(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_sorts_before_info() {
        let mut v = vec![Severity::Info, Severity::Critical, Severity::Medium];
        v.sort();
        assert_eq!(
            v,
            vec![Severity::Critical, Severity::Medium, Severity::Info]
        );
    }

    #[test]
    fn serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn label_upper_matches_variant() {
        assert_eq!(Severity::High.label_upper(), "HIGH");
    }
}

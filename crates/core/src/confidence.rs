use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Firm,
    Tentative,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Firm => "firm",
            Confidence::Tentative => "tentative",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_lowercase() {
        let json = serde_json::to_string(&Confidence::Firm).unwrap();
        assert_eq!(json, "\"firm\"");
    }
}

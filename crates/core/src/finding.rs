use crate::confidence::Confidence;
use crate::severity::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub param: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    #[serde(default)]
    pub proof: String,
    #[serde(default)]
    pub poc: String,
    #[serde(default)]
    pub remediation: String,
    /// Standards references for this weakness class — WSTG-v42 test IDs,
    /// CWE, CAPEC — from `standards::refs_for`. Stamped centrally by the
    /// orchestrator; machine-readable so reports/CI can group by standard.
    #[serde(default)]
    pub refs: Vec<String>,
}

impl Finding {
    pub fn new(
        check: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            check: check.into(),
            severity,
            title: title.into(),
            detail: detail.into(),
            evidence: String::new(),
            url: String::new(),
            param: String::new(),
            method: String::new(),
            payload: String::new(),
            confidence: None,
            proof: String::new(),
            poc: String::new(),
            remediation: String::new(),
            refs: Vec::new(),
        }
    }

    /// Attaches the standards refs for this finding's check (idempotent).
    pub fn with_standard_refs(mut self) -> Self {
        self.refs = crate::standards::refs_for(&self.check)
            .iter()
            .map(|s| s.to_string())
            .collect();
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }

    pub fn line(&self) -> String {
        let conf = match &self.confidence {
            Some(c) => format!(" ({})", c.as_str()),
            None => String::new(),
        };
        let refs = if self.refs.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.refs.join(" · "))
        };
        format!(
            "[{:<8}] {}{}: {} — {}{}",
            self.severity.label_upper(),
            self.check,
            conf,
            self.title,
            self.detail,
            refs
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_matches_expected_format() {
        let f = Finding::new(
            "sqli",
            Severity::Critical,
            "Error-based SQL injection",
            "payload surfaced a DB error",
        )
        .with_evidence("SQL syntax error near ...");
        assert_eq!(
            f.line(),
            "[CRITICAL] sqli: Error-based SQL injection — payload surfaced a DB error"
        );
    }

    #[test]
    fn line_includes_confidence_when_set() {
        let mut f = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "payload reflected unescaped",
        );
        f.confidence = Some(Confidence::Confirmed);
        assert_eq!(
            f.line(),
            "[HIGH    ] xss (confirmed): Reflected XSS — payload reflected unescaped"
        );
    }

    #[test]
    fn new_defaults_optional_fields_empty() {
        let f = Finding::new("recon", Severity::Info, "TLS version", "negotiated TLSv1.3");
        assert_eq!(f.evidence, "");
        assert_eq!(f.confidence, None);
    }
}

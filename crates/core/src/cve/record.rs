use crate::finding::Finding;
use serde::{Deserialize, Serialize};

pub const LOCAL_ASSIGNER_ORG_ID: &str = "pentest-toolkit-local";
pub const LOCAL_ID_PREFIX: &str = "PENTEST-LOCAL";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    #[serde(rename = "orgId")]
    pub org_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AffectedVersion {
    pub version: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub versions: Vec<AffectedVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemTypeDescription {
    pub lang: String,
    pub description: String,
    #[serde(rename = "cweId", skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemType {
    pub descriptions: Vec<ProblemTypeDescription>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CnaContainer {
    pub provider_metadata: ProviderMetadata,
    pub descriptions: Vec<Description>,
    pub affected: Vec<AffectedProduct>,
    pub references: Vec<Reference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_types: Option<Vec<ProblemType>>,
    #[serde(rename = "x_pentest", skip_serializing_if = "Option::is_none")]
    pub x_pentest: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Containers {
    pub cna: CnaContainer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveMetadata {
    pub cve_id: String,
    pub assigner_org_id: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveRecord {
    pub data_type: String,
    pub data_version: String,
    pub cve_metadata: CveMetadata,
    pub containers: Containers,
}

pub fn local_record(finding: &Finding, id_str: &str) -> CveRecord {
    let x_pentest = serde_json::json!({
        "check": finding.check,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "url": finding.url,
        "param": finding.param,
        "method": finding.method,
        "payload": finding.payload,
        "evidence": finding.evidence,
        "proof": finding.proof,
        "poc": finding.poc,
        "remediation": finding.remediation,
    });

    CveRecord {
        data_type: "CVE_RECORD".to_string(),
        data_version: "5.2.0".to_string(),
        cve_metadata: CveMetadata {
            cve_id: id_str.to_string(),
            assigner_org_id: LOCAL_ASSIGNER_ORG_ID.to_string(),
            state: "PUBLISHED".to_string(),
        },
        containers: Containers {
            cna: CnaContainer {
                provider_metadata: ProviderMetadata {
                    org_id: LOCAL_ASSIGNER_ORG_ID.to_string(),
                },
                descriptions: vec![Description {
                    lang: "en".to_string(),
                    value: finding.title.clone(),
                }],
                affected: vec![AffectedProduct {
                    vendor: "unknown".to_string(),
                    product: "target".to_string(),
                    versions: vec![AffectedVersion {
                        version: "*".to_string(),
                        status: "affected".to_string(),
                    }],
                }],
                references: vec![],
                problem_types: None,
                x_pentest: Some(x_pentest),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Severity;

    #[test]
    fn top_level_fields_use_camel_case() {
        let f = Finding::new("sqli", Severity::Critical, "title", "detail");
        let record = local_record(&f, "PENTEST-LOCAL-2026-000001");
        let json: serde_json::Value = serde_json::to_value(&record).unwrap();
        assert_eq!(json["dataType"], "CVE_RECORD");
        assert_eq!(json["dataVersion"], "5.2.0");
        assert_eq!(json["cveMetadata"]["cveId"], "PENTEST-LOCAL-2026-000001");
        assert_eq!(json["cveMetadata"]["assignerOrgId"], LOCAL_ASSIGNER_ORG_ID);
        assert_eq!(json["cveMetadata"]["state"], "PUBLISHED");
    }

    #[test]
    fn custom_data_field_is_literally_x_pentest_not_camel_cased() {
        let f = Finding::new("sqli", Severity::Critical, "title", "detail");
        let record = local_record(&f, "PENTEST-LOCAL-2026-000001");
        let json: serde_json::Value = serde_json::to_value(&record).unwrap();
        let cna = &json["containers"]["cna"];
        assert!(
            cna.get("x_pentest").is_some(),
            "expected literal x_pentest key, got: {cna}"
        );
        assert!(cna.get("xPentest").is_none());
        assert_eq!(cna["x_pentest"]["check"], "sqli");
    }

    #[test]
    fn descriptions_include_at_least_one_english_entry() {
        let f = Finding::new("xss", Severity::High, "Reflected XSS", "detail");
        let record = local_record(&f, "PENTEST-LOCAL-2026-000002");
        assert!(record
            .containers
            .cna
            .descriptions
            .iter()
            .any(|d| d.lang == "en"));
    }
}

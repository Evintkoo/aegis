use crate::finding::Finding;
use crate::severity::Severity;

#[derive(Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new() -> Self {
        Self { findings: Vec::new() }
    }

    pub fn add(&mut self, findings: Vec<Finding>) {
        self.findings.extend(findings);
    }

    pub fn write_cve_records(&self, writer: &crate::cve::CveWriter) -> std::io::Result<Vec<std::path::PathBuf>> {
        self.findings.iter().map(|f| writer.write_local(f)).collect()
    }

    pub fn sorted(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self.findings.iter().collect();
        v.sort_by_key(|f| f.severity);
        v
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.sorted()).unwrap_or_else(|_| "[]".to_string())
    }

    pub fn print_console(&self) {
        println!("{}", "=".repeat(64));
        println!("PENTEST REPORT — {} finding(s)", self.findings.len());
        println!("{}", "=".repeat(64));
        if self.findings.is_empty() {
            println!("No findings. (Absence of evidence != proof of safety.)");
            return;
        }
        for f in self.sorted() {
            println!("{}", f.line());
            if !f.evidence.is_empty() {
                let ev = if f.evidence.len() < 200 { f.evidence.clone() } else { format!("{}…", &f.evidence[..200]) };
                println!("           evidence   : {ev}");
            }
            if !f.proof.is_empty() {
                println!("           PROOF      : {}", f.proof);
            }
            if !f.poc.is_empty() {
                println!("           PoC        : {}", f.poc);
            }
            if !f.remediation.is_empty() {
                println!("           fix        : {}", f.remediation);
            }
        }
    }

    pub fn to_html(&self, meta: &[(String, String)]) -> String {
        let colors = |s: Severity| match s {
            Severity::Critical => "#b3123a",
            Severity::High => "#d1451b",
            Severity::Medium => "#c98a00",
            Severity::Low => "#2a7de1",
            Severity::Info => "#5c6672",
        };

        let mut counts: std::collections::BTreeMap<Severity, usize> = std::collections::BTreeMap::new();
        for f in &self.findings {
            *counts.entry(f.severity).or_insert(0) += 1;
        }
        let chips: String = counts
            .iter()
            .map(|(sev, n)| {
                format!(
                    "<span class=\"chip\" style=\"background:{}\">{} {}</span>",
                    colors(*sev),
                    sev.label_upper().to_lowercase(),
                    n
                )
            })
            .collect();

        let rows: String = self
            .sorted()
            .iter()
            .map(|f| {
                format!(
                    "<tr><td><span class=\"sev\" style=\"background:{}\">{}</span></td><td class=\"check\">{}</td><td><div class=\"title\">{}</div><div class=\"detail\">{}</div></td></tr>",
                    colors(f.severity),
                    html_escape(f.severity.label_upper()),
                    html_escape(&f.check),
                    html_escape(&f.title),
                    html_escape(&f.detail)
                )
            })
            .collect();

        let meta_rows: String = meta
            .iter()
            .map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", html_escape(k), html_escape(v)))
            .collect();

        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Pentest Report</title></head><body>\n<h1>Authorized Pentest Report</h1>\n<table class=\"meta\">{meta_rows}</table>\n<div class=\"chips\">{}</div>\n<table>{}</table>\n</body></html>",
            if chips.is_empty() { "<span class=\"chip\" style=\"background:#3aa76d\">no findings</span>".to_string() } else { chips },
            if rows.is_empty() { "<tr><td class=\"empty\">No findings.</td></tr>".to_string() } else { rows }
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity, title: &str) -> Finding {
        Finding::new("test", sev, title, "detail")
    }

    #[test]
    fn sorted_puts_critical_first() {
        let mut r = Report::new();
        r.add(vec![finding(Severity::Info, "a"), finding(Severity::Critical, "b")]);
        let sorted = r.sorted();
        assert_eq!(sorted[0].severity, Severity::Critical);
        assert_eq!(sorted[1].severity, Severity::Info);
    }

    #[test]
    fn to_json_round_trips_as_array() {
        let mut r = Report::new();
        r.add(vec![finding(Severity::High, "x")]);
        let json = r.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["title"], "x");
    }

    #[test]
    fn to_html_contains_severity_chip_and_escapes_input() {
        let mut r = Report::new();
        r.add(vec![finding(Severity::Critical, "<script>alert(1)</script>")]);
        let html = r.to_html(&[]);
        assert!(html.contains("CRITICAL"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn empty_report_html_says_no_findings() {
        let r = Report::new();
        let html = r.to_html(&[]);
        assert!(html.contains("No findings"));
    }

    #[test]
    fn write_cve_records_writes_one_file_per_finding() {
        use crate::cve::CveWriter;

        let dir = std::env::temp_dir().join(format!("pentest-core-report-cve-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let writer = CveWriter::new(&dir, 2026).unwrap();

        let mut r = Report::new();
        r.add(vec![finding(Severity::Critical, "a"), finding(Severity::High, "b")]);

        let paths = r.write_cve_records(&writer).unwrap();

        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert!(p.exists());
        }
    }
}

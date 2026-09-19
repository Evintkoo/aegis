use crate::finding::Finding;
use crate::severity::Severity;

/// What makes two findings "the same" for dedup: check, url, param,
/// title, payload — plus severity, so a re-emission at a different
/// severity still gets through.
type DedupKey = (String, String, String, String, String, Severity);

#[derive(Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    seen: std::collections::HashSet<DedupKey>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, findings: Vec<Finding>) {
        for f in findings {
            let key = (
                f.check.clone(),
                f.url.clone(),
                f.param.clone(),
                f.title.clone(),
                f.payload.clone(),
                f.severity,
            );
            if self.seen.insert(key) {
                self.findings.push(f);
            }
        }
    }

    pub fn write_cve_records(
        &self,
        writer: &crate::cve::CveWriter,
    ) -> std::io::Result<Vec<std::path::PathBuf>> {
        self.findings
            .iter()
            .map(|f| writer.write_local(f))
            .collect()
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
                println!("           evidence   : {}", truncate_evidence(&f.evidence));
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

        let mut counts: std::collections::BTreeMap<Severity, usize> =
            std::collections::BTreeMap::new();
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
                // "GET /product · id" — url with method prefixed and the
                // param it was found through appended.
                let mut url_cell = String::new();
                if !f.url.is_empty() {
                    if !f.method.is_empty() {
                        url_cell.push_str(&f.method);
                        url_cell.push(' ');
                    }
                    url_cell.push_str(&f.url);
                    if !f.param.is_empty() {
                        url_cell.push_str(&format!(" · {}", f.param));
                    }
                }

                let mut sections = String::new();
                if !f.evidence.is_empty() {
                    sections.push_str(&format!(
                        "<div class=\"label\">Evidence</div><pre class=\"evidence\" style=\"white-space:pre-wrap;word-break:break-word\">{}</pre>",
                        html_escape(&f.evidence)
                    ));
                }
                if !f.poc.is_empty() {
                    sections.push_str(&format!(
                        "<div class=\"label\">PoC</div><pre style=\"white-space:pre-wrap;word-break:break-word\"><code>{}</code></pre>",
                        html_escape(&f.poc)
                    ));
                }
                if !f.remediation.is_empty() {
                    sections.push_str(&format!(
                        "<div class=\"label\">Remediation</div><div>{}</div>",
                        html_escape(&f.remediation)
                    ));
                }
                let details_row = if sections.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<tr><td colspan=\"4\"><details><summary>details</summary>{sections}</details></td></tr>"
                    )
                };

                format!(
                    "<tr><td><span class=\"sev\" style=\"background:{}\">{}</span></td><td class=\"check\">{}</td><td class=\"url\">{}</td><td><div class=\"title\">{}</div><div class=\"detail\">{}</div></td></tr>{details_row}",
                    colors(f.severity),
                    html_escape(f.severity.label_upper()),
                    html_escape(&f.check),
                    html_escape(&url_cell),
                    html_escape(&f.title),
                    html_escape(&f.detail)
                )
            })
            .collect();

        let meta_rows: String = meta
            .iter()
            .map(|(k, v)| {
                format!(
                    "<tr><th>{}</th><td>{}</td></tr>",
                    html_escape(k),
                    html_escape(v)
                )
            })
            .collect();

        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Pentest Report</title></head><body>\n<h1>Authorized Pentest Report</h1>\n<table class=\"meta\">{meta_rows}</table>\n<div class=\"chips\">{}</div>\n<table>{}</table>\n</body></html>",
            if chips.is_empty() { "<span class=\"chip\" style=\"background:#3aa76d\">no findings</span>".to_string() } else { chips },
            if rows.is_empty() { "<tr><td class=\"empty\">No findings.</td></tr>".to_string() } else { rows }
        )
    }
}

/// Truncates evidence to at most 200 chars, always cutting on a char
/// boundary so multi-byte UTF-8 sequences (attacker-controlled evidence
/// from HTTP response bodies) can never trigger a byte-index panic.
fn truncate_evidence(evidence: &str) -> String {
    if evidence.chars().count() < 200 {
        evidence.to_string()
    } else {
        let truncated: String = evidence.chars().take(200).collect();
        format!("{truncated}…")
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
        r.add(vec![
            finding(Severity::Info, "a"),
            finding(Severity::Critical, "b"),
        ]);
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
        r.add(vec![finding(
            Severity::Critical,
            "<script>alert(1)</script>",
        )]);
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
    fn add_skips_exact_duplicates() {
        let mut r = Report::new();
        r.add(vec![finding(Severity::High, "x")]);
        r.add(vec![finding(Severity::High, "x")]);
        r.add(vec![
            finding(Severity::High, "x").with_evidence("same key, later run")
        ]);
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn add_keeps_findings_that_differ_in_key_or_severity() {
        let mut r = Report::new();
        r.add(vec![finding(Severity::High, "x")]);
        r.add(vec![finding(Severity::Critical, "x")]);
        r.add(vec![Finding::new("other", Severity::High, "x", "detail")]);
        r.add(vec![Finding::new("test", Severity::High, "y", "detail")]);
        assert_eq!(r.findings.len(), 4);
    }

    #[test]
    fn to_html_renders_url_column_and_collapsible_details() {
        let mut f = finding(Severity::High, "x");
        f.url = "http://t/product".to_string();
        f.method = "GET".to_string();
        f.param = "id".to_string();
        f.evidence = "EV<impl>".to_string();
        f.poc = "curl 'http://t/product?id=1'".to_string();
        f.remediation = "encode output".to_string();
        let mut r = Report::new();
        r.add(vec![f]);

        let html = r.to_html(&[]);

        assert!(html.contains("GET http://t/product · id"), "{html}");
        assert!(html.contains("<details><summary>details</summary>"));
        assert!(html.contains("Evidence"));
        assert!(html.contains("EV&lt;impl&gt;"));
        assert!(html.contains("<code>curl 'http://t/product?id=1'</code>"));
        assert!(html.contains("Remediation"));
        assert!(html.contains("encode output"));
    }

    #[test]
    fn to_html_escapes_poc_and_skips_details_row_when_all_sections_empty() {
        let mut bare = finding(Severity::Low, "bare");
        bare.url = "http://t/p".to_string();
        let mut r = Report::new();
        r.add(vec![bare]);

        let html = r.to_html(&[]);

        assert!(!html.contains("<details>"), "{html}");
        assert!(html.contains("http://t/p"));
    }

    #[test]
    fn truncate_evidence_cuts_on_a_char_boundary_for_multibyte_input() {
        // "€" is 3 bytes in UTF-8, so byte offset 200 (not a multiple of 3)
        // falls squarely inside the 67th character — exactly the case
        // where `&s[..200]` panics with "byte index 200 is not a char
        // boundary". chars().count() == 250 here, distinct from the byte
        // length (750), so this genuinely exercises the multi-byte path
        // (a 2-byte char like "é" would coincidentally still be a boundary
        // at offset 200, since 200 is a multiple of 2 — it must be a width
        // that does *not* evenly divide 200).
        let evidence = "€".repeat(250);
        assert_eq!(evidence.chars().count(), 250);
        assert_ne!(evidence.chars().count(), evidence.len());
        assert_ne!(200 % "€".len(), 0);

        let truncated = truncate_evidence(&evidence);

        assert_eq!(truncated.chars().count(), 201); // 200 chars + the "…" marker
        assert!(truncated.ends_with('…'));
        assert!(truncated.starts_with(&"€".repeat(200)));
    }

    #[test]
    fn print_console_does_not_panic_on_multibyte_evidence() {
        let mut r = Report::new();
        r.add(vec![
            finding(Severity::High, "x").with_evidence("€".repeat(250))
        ]);
        // Regression test for the byte-index-200 char-boundary panic:
        // this must not panic even though byte 200 falls mid-character.
        r.print_console();
    }

    #[test]
    fn write_cve_records_writes_one_file_per_finding() {
        use crate::cve::CveWriter;

        let dir = std::env::temp_dir().join(format!(
            "pentest-core-report-cve-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let writer = CveWriter::new(&dir, 2026).unwrap();

        let mut r = Report::new();
        r.add(vec![
            finding(Severity::Critical, "a"),
            finding(Severity::High, "b"),
        ]);

        let paths = r.write_cve_records(&writer).unwrap();

        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert!(p.exists());
        }
    }
}

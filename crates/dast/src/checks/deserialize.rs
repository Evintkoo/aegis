//! deserialize — unsafe deserialization probe (CWE-502, DAST side).
//!
//! Sends *harmless marker* payloads shaped like the serialization formats
//! frameworks auto-detect, and flags when the response leaks a
//! deserialization-engine error signature. No gadget chains, no
//! exploitation: the markers are inert (an empty Java-serialized header,
//! an empty PHP object, a .NET type hint) — a vulnerable endpoint
//! betrays itself by erroring distinctively, not by executing anything.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "deserialize";

const PROBES: &[(&str, &str, &[&str])] = &[
    (
        "rO0ABQ==",
        "Java serialization marker (base64 AC ED 00 05)",
        &[
            "ObjectInputStream",
            "readObject",
            "InvalidClassException",
            "ClassNotFoundException",
            "ObjectStreamException",
        ],
    ),
    (
        "O:8:\"stdClass\":0:{}",
        "PHP serialize() object",
        &[
            "unserialize()",
            "__PHP_Incomplete_Class",
            "Warning: unserialize",
        ],
    ),
    (
        "{\"__type\":\"System.IntPtr\"}",
        ".NET TypeNameHandling hint",
        &[
            "JsonSerializationException",
            "SerializationException",
            "TypeNameHandling",
            "Runtime.Serialization",
        ],
    ),
    (
        "gASV",
        "Python pickle marker",
        &["UnpicklingError", "pickle.loads", "_pickle."],
    ),
];

fn matches_signature(body: &str, signatures: &[&str]) -> Option<String> {
    signatures
        .iter()
        .find(|s| body.contains(*s))
        .map(|s| s.to_string())
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(param) = &opts.param else {
        return out;
    };
    let method = opts.method.to_uppercase();
    let base = if opts.base_value.is_empty() {
        "1"
    } else {
        &opts.base_value
    };

    for (payload, family, signatures) in PROBES {
        let val = format!("{base}{payload}");
        let req = if method == "POST" {
            HttpRequest::post().form_field(param, &val)
        } else {
            HttpRequest::get().param(param, &val)
        };
        let Ok(r) = client.request(req).await else {
            continue;
        };
        if let Some(sig) = matches_signature(&r.body, signatures) {
            let mut f = Finding::new(
                NAME,
                Severity::High,
                "Unsafe deserialization error signature",
                format!("{family} triggered a native deserializer error (param '{param}')"),
            )
            .with_evidence(sig);
            f.payload = val;
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::HttpClientConfig;

    fn fast_client(base_url: String) -> HttpClient {
        HttpClient::new(
            base_url,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                ..HttpClientConfig::default()
            },
        )
    }

    #[tokio::test]
    async fn detects_a_java_deserialization_error_signature() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("data").cloned().unwrap_or_default();
            if v.contains("rO0ABQ") {
                ScriptedResponse::ok("java.io.InvalidClassException: local class incompatible")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("data".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings
            .iter()
            .any(|f| f.title.contains("deserialization") && f.evidence == "InvalidClassException"));
    }

    #[tokio::test]
    async fn detects_a_php_unserialize_warning() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("data").cloned().unwrap_or_default();
            if v.contains("stdClass") {
                ScriptedResponse::ok("Warning: unserialize(): Error at offset 0 of 20 bytes")
            } else {
                ScriptedResponse::ok("ok")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("data".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.evidence.contains("unserialize")));
    }

    #[tokio::test]
    async fn a_clean_endpoint_that_just_echoes_the_marker_is_not_flagged() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("data").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("echo: {v}"))
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("data".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "echoing the inert marker is not a vulnerability, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn returns_empty_without_a_param() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        assert!(run_impl(&client, &Opts::default()).await.is_empty());
    }
}

//! graphql — detect exposed GraphQL endpoints with introspection enabled.
//! Port of `checks/graphql.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "graphql";

const ENDPOINTS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/graphql/console",
    "/graphiql",
    "/playground",
    "/api/graphql/v1",
];

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = client.base_url_root();

    for ep in ENDPOINTS {
        let url = format!("{root}{ep}");
        let Ok(r) = client
            .request(
                HttpRequest::post()
                    .url(&url)
                    .json(serde_json::json!({"query": "{__schema{types{name}}}"})),
            )
            .await
        else {
            continue;
        };
        if r.status == 200 && r.body.contains("__schema") {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&r.body) {
                if let Some(types) = data
                    .get("data")
                    .and_then(|d| d.get("__schema"))
                    .and_then(|s| s.get("types"))
                    .and_then(|t| t.as_array())
                {
                    if !types.is_empty() {
                        out.push(
                            Finding::new(
                                NAME,
                                Severity::High,
                                "GraphQL introspection enabled",
                                format!("{ep} exposes full schema ({} types)", types.len()),
                            )
                            .with_evidence(ep.to_string()),
                        );
                        return out;
                    }
                }
            }
        }
        let Ok(g) = client.request(HttpRequest::get().url(&url)).await else {
            continue;
        };
        let lower = g.body.to_lowercase();
        if g.status == 200 && (lower.contains("graphiql") || lower.contains("playground")) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "GraphQL IDE exposed",
                    format!("{ep} serves an interactive GraphQL IDE"),
                )
                .with_evidence(ep.to_string()),
            );
            return out;
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
    async fn detects_introspection_enabled() {
        let base = scripted_server(|req, _| {
            if req.path == "/graphql" && req.body.contains("__schema") {
                ScriptedResponse::ok(
                    r#"{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}"#,
                )
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings
            .iter()
            .any(|f| f.title == "GraphQL introspection enabled" && f.detail.contains("2 types")));
    }

    #[tokio::test]
    async fn detects_ide_exposed_when_introspection_is_disabled() {
        let base = scripted_server(|req, _| {
            if req.path == "/graphql" {
                ScriptedResponse::ok("<html><body>GraphiQL</body></html>")
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.iter().any(|f| f.title == "GraphQL IDE exposed"));
    }

    #[tokio::test]
    async fn no_findings_when_no_endpoint_exists() {
        let base = scripted_server(|_req, _| ScriptedResponse::with_status(404, "not found")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }
}

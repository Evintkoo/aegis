//! api_docs — exposed API documentation (Swagger/OpenAPI/Redoc) probes.
//!
//! Machine-readable API contracts handed to anonymous visitors are an
//! attack-surface map: every path, parameter, and model in one document.
//! Detection is signature-based on the doc itself (an `openapi`/`swagger`
//! document key, a Swagger-UI/FastAPI page title), not on the status code
//! alone — a 200 on `/docs` that is just the app's human docs page is not
//! flagged.
//!
//! Read-only GETs against a bounded path list; part of the default run.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "api_docs";

const PATHS: &[&str] = &[
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger-ui.html",
    "/swagger/",
    "/docs",
    "/redoc",
];

/// Decides whether a response body is an API doc / doc UI. Exposed for
/// testing: the signatures are deliberately narrow — JSON document keys
/// (`"openapi":`, `"swagger":`) or actual doc-UI titles, not generic words.
pub fn looks_like_api_doc(body: &str) -> bool {
    let lower = body.to_lowercase();
    // Raw OpenAPI/Swagger documents carry these as top-level JSON keys.
    lower.contains("\"openapi\"") || lower.contains("\"swagger\":") || lower.contains("'<script src=\"swagger") ||
        // Doc UIs identify themselves in the page title.
        lower.contains("<title>swagger ui") || lower.contains("<title>redoc") ||
        // FastAPI's generated docs page.
        (lower.contains("fastapi") && lower.contains("swagger ui"))
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = client.base_url_root();

    for path in PATHS {
        let url = format!("{root}{path}");
        let Ok(r) = client.request(HttpRequest::get().url(&url)).await else {
            continue;
        };
        if r.status == 200 && looks_like_api_doc(&r.body) {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "API documentation exposed",
                    format!(
                        "{path} serves an API contract/UI to unauthenticated visitors — every endpoint, parameter, and data model is enumerable"
                    ),
                )
                .with_evidence(url),
            );
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
    async fn flags_an_exposed_openapi_document() {
        let base = scripted_server(|req, _| {
            if req.path == "/openapi.json" {
                ScriptedResponse::ok(r#"{"openapi":"3.0.0","info":{"title":"api"}}"#)
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.ends_with("/openapi.json"));
    }

    #[tokio::test]
    async fn flags_a_swagger_ui_page() {
        let base = scripted_server(|req, _| {
            if req.path == "/swagger-ui.html" {
                ScriptedResponse::ok("<html><head><title>Swagger UI</title></head></html>")
            } else {
                ScriptedResponse::with_status(404, "not found")
            }
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn a_200_human_docs_page_is_not_flagged() {
        let base = scripted_server(|_req, _| {
            ScriptedResponse::ok(
                "<html><head><title>Project documentation</title></head><body>manual</body></html>",
            )
        })
        .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn doc_signatures_are_narrow() {
        assert!(looks_like_api_doc(r#"{"openapi": "3.1.0"}"#));
        assert!(looks_like_api_doc(r#"{"swagger": "2.0"}"#));
        assert!(looks_like_api_doc("<title>Swagger UI</title>"));
        assert!(looks_like_api_doc("<title>ReDoc</title>"));
        assert!(!looks_like_api_doc("we use swagger at work, ask bob"));
        assert!(!looks_like_api_doc("<title>Home</title>"));
        assert!(!looks_like_api_doc(""));
    }
}

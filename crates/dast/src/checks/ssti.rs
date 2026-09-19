//! ssti — Server-Side Template Injection.
//!
//! Uses arithmetic markers unlikely to collide with page content: if the
//! template engine evaluates the expression, the product appears in the
//! response. Port of `checks/ssti.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "ssti";

// (payload, expected rendered marker) -- 31337*3 products are unique enough
const PROBES: &[(&str, &str)] = &[
    ("{{31337*3}}", "94011"),        // Jinja2 / Twig
    ("${31337*3}", "94011"),         // FreeMarker / JSP EL / Mako
    ("#{31337*3}", "94011"),         // Ruby / Thymeleaf
    ("<%= 31337*3 %>", "94011"),     // ERB / EJS
    ("${{31337*3}}", "94011"),       // nested
    ("*{31337*3}", "94011"),         // Thymeleaf selection
    ("{31337*3}", "94011"),          // Smarty
    ("#set($x=31337*3)$x", "94011"), // Velocity
    ("{{= 31337*3 }}", "94011"),     // doT / underscore
    ("@(31337*3)", "94011"),         // Razor
    ("{{'a'*3}}", "aaa"),            // Jinja string mult (engine, not just math)
];

async fn send(
    client: &HttpClient,
    method: &str,
    param: &str,
    val: &str,
) -> Option<pentest_core::HttpResponse> {
    let req = if method == "POST" {
        HttpRequest::post().form_field(param, val)
    } else {
        HttpRequest::get().param(param, val)
    };
    client.request(req).await.ok()
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
        "x"
    } else {
        &opts.base_value
    };

    let Some(baseline) = send(client, &method, param, &format!("{base}zzq")).await else {
        return out;
    };

    for (payload, marker) in PROBES {
        let val = format!("{base}{payload}");
        let Some(r) = send(client, &method, param, &val).await else {
            continue;
        };
        // rendered marker present AND raw payload NOT reflected verbatim => evaluated
        if r.body.contains(marker) && !baseline.body.contains(marker) && !r.body.contains(payload) {
            let mut f = Finding::new(
                NAME,
                Severity::Critical,
                "Server-Side Template Injection",
                format!("payload {payload:?} evaluated to {marker:?}"),
            )
            .with_evidence(format!("param '{param}' -> engine executed expression"));
            f.payload = val;
            f.proof = format!("expression {payload} evaluated server-side to {marker}");
            out.push(f);
            break;
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
        let config = HttpClientConfig {
            delay: std::time::Duration::from_millis(0),
            ..HttpClientConfig::default()
        };
        HttpClient::new(base_url, config)
    }

    #[tokio::test]
    async fn detects_jinja_style_evaluation() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("name").cloned().unwrap_or_default();
            if v == "1{{31337*3}}" {
                ScriptedResponse::ok("Hello 94011")
            } else {
                ScriptedResponse::ok(format!("Hello {v}"))
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("name".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Server-Side Template Injection");
        assert!(findings[0].proof.contains("94011"));
    }

    #[tokio::test]
    async fn no_finding_when_marker_appears_but_payload_is_also_reflected_verbatim() {
        // A page that echoes the raw, unevaluated payload back (e.g. in a
        // debug message) AND happens to contain the marker digits
        // elsewhere (coincidence, not evaluation) must not be flagged --
        // that's exactly what the "payload not in body" guard is for.
        let base = scripted_server(|req, _| {
            // Match the FULL injected value exactly -- several probes share
            // substrings (e.g. "${{31337*3}}" contains "{{31337*3}}"), so a
            // substring check here would fire for more than one probe.
            let v = req.query.get("name").cloned().unwrap_or_default();
            if v == "1{{31337*3}}" {
                ScriptedResponse::ok("echo: {{31337*3}} | unrelated page counter: 94011")
            } else {
                ScriptedResponse::ok(format!("echo: {v}"))
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("name".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "marker text coinciding with a verbatim-reflected payload must not count as SSTI"
        );
    }

    #[tokio::test]
    async fn returns_empty_without_a_param() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);
        let findings = run_impl(&client, &Opts::default()).await;
        assert!(findings.is_empty());
    }
}

//! xss — reflected cross-site-scripting probe.
//!
//! Injects unique markers and checks whether they come back unencoded in
//! an HTML-dangerous context. Detection only -- never executes anything.
//! Port of `checks/xss.py`.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "xss";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Tag,
    Attr,
    Js,
    Plain,
}

// Each marker is unique so we can confirm reflection unambiguously; the
// context tag is where the payload must land to execute.
const PROBES: &[(&str, &str, &str, Ctx)] = &[
    (
        "<zqx1>alert</zqx1>",
        "<zqx1>",
        "raw HTML tag reflected unencoded",
        Ctx::Tag,
    ),
    (
        "\"zqx2'>",
        "\"zqx2'>",
        "quote/angle-bracket breakout reflected unencoded",
        Ctx::Attr,
    ),
    (
        "javascript:zqx3",
        "javascript:zqx3",
        "javascript: scheme reflected unencoded inside an attribute",
        Ctx::Attr,
    ),
    (
        "\"><svg/onload=zzq4()>",
        "\"><svg/onload=zzq4()>",
        "attribute-breakout with an event handler reflected unencoded",
        Ctx::Attr,
    ),
    (
        "';zzq5();//",
        "';zzq5();//",
        "script-context breakout reflected unencoded",
        Ctx::Js,
    ),
];

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn slice_around(body: &str, idx: usize, len: usize, radius: usize) -> &str {
    let start = (0..=idx.saturating_sub(radius))
        .rev()
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(idx);
    let end = ((idx + len + radius).min(body.len())..=(idx + len))
        .rev()
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(idx + len);
    &body[start..end]
}

fn slice_before(body: &str, idx: usize, radius: usize) -> &str {
    let start = (0..=idx.saturating_sub(radius))
        .rev()
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(idx);
    &body[start..idx]
}

fn context_at(body: &str, idx: usize) -> Ctx {
    let before = slice_before(body, idx, 120);
    if let Some(s) = before.rfind("<script") {
        if !before[s..].contains("</script") {
            return Ctx::Js;
        }
    }
    match before.rfind('<') {
        Some(lt) if before.rfind('>').is_none_or(|gt| gt < lt) => {
            let seg = &before[lt..];
            let quotes = seg.matches('"').count() + seg.matches('\'').count();
            if quotes % 2 == 1 {
                Ctx::Attr
            } else {
                Ctx::Tag
            }
        }
        _ => Ctx::Plain,
    }
}

fn attr_sink_before(body: &str, idx: usize) -> bool {
    let before = slice_before(body, idx, 100);
    ["href=", "src=", "action="]
        .iter()
        .any(|a| before.contains(a))
        || before
            .as_bytes()
            .windows(2)
            .any(|w| w[0].is_ascii_whitespace() && w[1] == b'=')
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
        "test"
    } else {
        &opts.base_value
    };

    for (payload, needle, why, expected) in PROBES {
        let val = format!("{base}{payload}");
        let req = if method == "POST" {
            HttpRequest::post().form_field(param, &val)
        } else {
            HttpRequest::get().param(param, &val)
        };
        let Ok(r) = client.request(req).await else {
            continue;
        };
        let body = &r.body;
        let Some(idx) = body.find(needle) else {
            continue;
        };

        let ctype = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if !ctype.is_empty() && !ctype.to_lowercase().contains("html") {
            continue;
        }

        // An html-escaped copy of the needle right around the raw reflection
        // means that sink is entity-encoded; an escaped copy elsewhere on the
        // page says nothing about this reflection point.
        let escaped = html_escape(needle);
        if escaped != *needle && slice_around(body, idx, needle.len(), 120).contains(&escaped) {
            continue;
        }

        let context = context_at(body, idx);
        let high = match expected {
            Ctx::Js => context == Ctx::Js,
            Ctx::Tag | Ctx::Plain => context != Ctx::Plain,
            Ctx::Attr if needle.starts_with("javascript:") => attr_sink_before(body, idx),
            Ctx::Attr => context != Ctx::Plain,
        };

        let snippet_start = idx.saturating_sub(40);
        let snippet_end = (idx + needle.len() + 20).min(body.len());
        let snippet = body[snippet_start..snippet_end].replace('\n', " ");
        let (severity, title, detail) = if high {
            (
                Severity::High,
                "Reflected XSS",
                format!("{why} (param '{param}')"),
            )
        } else {
            (
                Severity::Info,
                "XSS payload unencoded in text context",
                format!("payload echoed unencoded in text context (param '{param}')"),
            )
        };
        let mut f = Finding::new(NAME, severity, title, detail).with_evidence(snippet);
        f.payload = val;
        out.push(f);
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
    async fn raw_reflection_in_a_text_node_yields_info_not_high() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("<html><body>results for: {v}</body></html>"))
                .header("Content-Type", "text/html")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("q".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            !findings.iter().any(|f| f.severity == Severity::High),
            "text-node-only reflection must not be High: {findings:?}"
        );
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Info && f.detail.contains("text context")));
    }

    #[tokio::test]
    async fn attribute_breakout_reflection_flags_high() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!(
                "<html><body><a href=\"/x\" title=\"{v}\">link</a></body></html>"
            ))
            .header("Content-Type", "text/html")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("q".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.iter().any(|f| f.severity == Severity::High
                && f.title == "Reflected XSS"
                && f.payload.contains("zzq4")),
            "findings={findings:?}"
        );
    }

    #[tokio::test]
    async fn escaped_copy_beside_the_raw_reflection_still_suppresses() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!(
                "<html><body>results for: {v} [{}]</body></html>",
                html_escape(&v)
            ))
            .header("Content-Type", "text/html")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("q".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(!findings.iter().any(|f| f.severity == Severity::High));
    }

    #[tokio::test]
    async fn escaped_copy_far_from_the_raw_reflection_does_not_suppress() {
        let filler = "x".repeat(150);
        let base = scripted_server(move |req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!(
                "<p>{}</p>{filler}<main>{v}</main>",
                html_escape(&v)
            ))
            .header("Content-Type", "text/html")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("q".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.iter().any(|f| f.payload.contains("zqx1")),
            "zqx1 reflection must survive an escaped copy far away: findings={findings:?}"
        );
    }

    #[tokio::test]
    async fn ignores_html_escaped_reflection() {
        // The javascript:zqx3 probe has no HTML-special characters, so
        // entity-escaping can never visibly change it -- a real app
        // defends against that probe by rejecting/stripping the value
        // outright (a URL-scheme allow-list), not by HTML-escaping it.
        // Simulate exactly that split defense here.
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            if v.contains("zqx3") {
                ScriptedResponse::ok("<html><body>results for: (rejected)</body></html>")
                    .header("Content-Type", "text/html")
            } else {
                ScriptedResponse::ok(format!(
                    "<html><body>results for: {}</body></html>",
                    html_escape(&v)
                ))
                .header("Content-Type", "text/html")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("q".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "HTML-escaped (or scheme-rejected) reflection must not be flagged"
        );
    }

    #[tokio::test]
    async fn ignores_reflection_in_a_json_response() {
        let base = scripted_server(|req, _| {
            let v = req.query.get("q").cloned().unwrap_or_default();
            ScriptedResponse::ok(format!("{{\"query\":\"{v}\"}}"))
                .header("Content-Type", "application/json")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts {
            param: Some("q".to_string()),
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings.is_empty(),
            "non-HTML content types must not be flagged even if reflected raw"
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

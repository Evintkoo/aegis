pub mod cache_deception;
pub mod clickjacking;
pub mod cmdi;
pub mod content_discovery;
pub mod cors_advanced;
pub mod crlf;
pub mod csrf;
pub mod files;
pub mod headers;
pub mod host_header;
pub mod idor;
pub mod ldap_injection;
pub mod method_tampering;
pub mod nosqli;
pub mod recon;
pub mod redirect;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod traversal;
pub mod xpath_injection;
pub mod xss;
pub mod xxe;

#[cfg(test)]
pub(crate) mod test_support;

/// Crude structural similarity of two response bodies, ported from the
/// Python toolkit's `_sim()` (duplicated verbatim across 5 check modules
/// there -- sqli/nosqli/ldap_injection/xpath_injection/idor): the ratio of
/// the shorter length to the longer, used as a cheap "did the response
/// change shape" signal for boolean-blind and behavior-change detection.
/// Not a text-similarity algorithm -- matches the original's length-ratio
/// heuristic exactly, including its blind spot (same-length,
/// different-content bodies read as identical). Uses byte length rather
/// than char count (Python's `len()` on `str` is a char count) -- for the
/// near-entirely-ASCII HTML/JSON bodies these checks compare, the
/// difference is immaterial to a coarse length-ratio signal.
pub(crate) fn similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let m = a.len().max(b.len());
    if m == 0 {
        1.0
    } else {
        a.len().min(b.len()) as f64 / m as f64
    }
}

/// The client's configured base URL with any query string and trailing
/// slash stripped, e.g. `https://x.test/item?id=1` -> `https://x.test/item`.
/// Ported from the one-liner (`client.base_url.split("?")[0].rstrip("/")`)
/// that `cache_deception.py`, `info_disclosure.py`, and
/// `method_tampering.py` each duplicate inline in Python -- factored out
/// here the same way `similarity()` was, since three Rust check modules
/// need it too. Distinct from `HttpClient::base_url_root()`, which drops
/// the path entirely rather than just the query string.
pub(crate) fn path_root(base_url: &str) -> String {
    base_url.split('?').next().unwrap_or(base_url).trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::{HttpClient, HttpClientConfig, HttpRequest};

    #[tokio::test]
    async fn scripted_server_answers_multiple_sequential_requests() {
        let base = scripted_server(|req, _self_url| {
            if req.query.get("id").map(|v| v.as_str()) == Some("SLEEP") {
                ScriptedResponse::delayed("slow", 150)
            } else {
                ScriptedResponse::ok(format!("got:{}", req.query.get("id").cloned().unwrap_or_default()))
            }
        })
        .await;
        let client = HttpClient::new(base, HttpClientConfig::default());

        let r1 = client.request(HttpRequest::get().param("id", "1")).await.unwrap();
        assert_eq!(r1.body, "got:1");

        let start = std::time::Instant::now();
        let r2 = client.request(HttpRequest::get().param("id", "SLEEP")).await.unwrap();
        assert_eq!(r2.body, "slow");
        assert!(start.elapsed() >= std::time::Duration::from_millis(140));

        let r3 = client.request(HttpRequest::post().form_field("id", "3")).await.unwrap();
        assert_eq!(r3.status, 200);
    }

    #[tokio::test]
    async fn request_level_header_overrides_client_level_header() {
        let base = scripted_server(|req, _self_url| {
            let auth: Vec<_> = req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Authorization")).collect();
            ScriptedResponse::ok(format!("count={} val={:?}", auth.len(), auth.first().map(|(_, v)| v.clone())))
        })
        .await;
        let mut config = HttpClientConfig::default();
        config.headers.insert("Authorization".to_string(), "secret".to_string());
        let client = HttpClient::new(base, config);

        let r = client.request(HttpRequest::get().header("Authorization", "")).await.unwrap();
        assert_eq!(r.body, "count=1 val=Some(\"\")");
        assert!(client.header("authorization").is_some());
    }
}

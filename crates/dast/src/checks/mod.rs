pub mod cmdi;
pub mod crlf;
pub mod content_discovery;
pub mod files;
pub mod headers;
pub mod nosqli;
pub mod recon;
pub mod sqli;
pub mod ssti;
pub mod traversal;
pub mod xss;

#[cfg(test)]
pub(crate) mod test_support;

#[allow(dead_code)]
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

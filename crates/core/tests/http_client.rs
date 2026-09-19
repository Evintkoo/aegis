mod support;

use pentest_core::{HttpClient, HttpClientConfig, HttpRequest};
use support::{one_shot_server, TestResponse};

#[test]
fn base_url_returns_the_configured_base_url() {
    let client = HttpClient::new("https://example.test", HttpClientConfig::default());
    assert_eq!(client.base_url(), "https://example.test");
}

#[test]
fn base_url_root_strips_path_and_query_but_keeps_scheme_host_and_port() {
    let client = HttpClient::new("https://x.test:8443/path?q=1", HttpClientConfig::default());
    assert_eq!(client.base_url_root(), "https://x.test:8443");
}

#[tokio::test]
async fn get_request_returns_status_and_body() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("hello")).await;
    let client = HttpClient::new(base_url, HttpClientConfig::default());

    let resp = client.request(HttpRequest::get()).await.unwrap();

    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "hello");
    let recorded = rx.await.unwrap();
    assert_eq!(recorded.method, "GET");
}

#[tokio::test]
async fn get_params_override_existing_query_value() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("ok")).await;
    let client = HttpClient::new(format!("{base_url}/item?id=1"), HttpClientConfig::default());

    client
        .request(HttpRequest::get().param("id", "999"))
        .await
        .unwrap();

    let recorded = rx.await.unwrap();
    assert!(recorded.path_and_query.contains("id=999"));
    assert!(
        !recorded.path_and_query.contains("id=1&") && !recorded.path_and_query.ends_with("id=1")
    );
}

#[tokio::test]
async fn post_form_sends_url_encoded_body() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("ok")).await;
    let client = HttpClient::new(base_url, HttpClientConfig::default());

    client
        .request(HttpRequest::post().form_field("username", "a b"))
        .await
        .unwrap();

    let recorded = rx.await.unwrap();
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.body, "username=a+b");
}

#[tokio::test]
async fn custom_header_is_sent() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("ok")).await;
    let mut config = HttpClientConfig::default();
    config
        .headers
        .insert("X-Test".to_string(), "abc".to_string());
    let client = HttpClient::new(base_url, config);

    client.request(HttpRequest::get()).await.unwrap();

    let recorded = rx.await.unwrap();
    assert!(recorded
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-test") && v == "abc"));
}

#[tokio::test]
async fn first_request_on_a_fresh_client_is_not_delayed() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("one")).await;
    let config = HttpClientConfig {
        delay: std::time::Duration::from_millis(300),
        ..HttpClientConfig::default()
    };
    let client = HttpClient::new(base_url, config);

    let start = std::time::Instant::now();
    client.request(HttpRequest::get()).await.unwrap();
    let _ = rx.await.unwrap();

    assert!(start.elapsed() < std::time::Duration::from_millis(150));
}

#[tokio::test]
async fn second_request_on_the_same_client_is_rate_limited() {
    let (base_url_a, rx_a) = one_shot_server(TestResponse::ok("one")).await;
    let (base_url_b, rx_b) = one_shot_server(TestResponse::ok("two")).await;

    let config = HttpClientConfig {
        delay: std::time::Duration::from_millis(200),
        ..HttpClientConfig::default()
    };
    let client = HttpClient::new(base_url_a.clone(), config);

    let start = std::time::Instant::now();
    client.request(HttpRequest::get()).await.unwrap();
    let _ = rx_a.await.unwrap();

    // Same client, different URL per-request (base_url is just the default) — the rate
    // limit lives on the client, not on any particular target URL.
    client
        .request(HttpRequest::get().url(base_url_b))
        .await
        .unwrap();
    let _ = rx_b.await.unwrap();

    assert!(start.elapsed() >= std::time::Duration::from_millis(200));
}

#[tokio::test]
async fn concurrent_requests_on_the_same_client_are_serialized_by_the_rate_limiter() {
    let (base_url_prime, rx_prime) = one_shot_server(TestResponse::ok("zero")).await;
    let (base_url_a, rx_a) = one_shot_server(TestResponse::ok("one")).await;
    let (base_url_b, rx_b) = one_shot_server(TestResponse::ok("two")).await;

    let config = HttpClientConfig {
        delay: std::time::Duration::from_millis(200),
        ..HttpClientConfig::default()
    };
    let client = HttpClient::new(base_url_prime, config);

    // Prime the client so `last` is fresh going into the timed section below:
    // every request from here on must actually wait out the full delay,
    // rather than the very first call on a client getting a free pass.
    client.request(HttpRequest::get()).await.unwrap();
    let _ = rx_prime.await.unwrap();

    let start = std::time::Instant::now();
    // Fire two requests concurrently on the same primed client. If the rate
    // limiter drops its lock before sleeping (the bug), both calls read the
    // same stale `last`, both compute ~the same wait, and both sleep in
    // parallel — the pair finishes in about one delay period. A rate
    // limiter that holds the lock across the sleep forces the second call
    // to queue behind the first, so the pair must span roughly two delay
    // periods back-to-back.
    let (r1, r2) = tokio::join!(
        client.request(HttpRequest::get().url(base_url_a)),
        client.request(HttpRequest::get().url(base_url_b))
    );
    r1.unwrap();
    r2.unwrap();
    let _ = rx_a.await.unwrap();
    let _ = rx_b.await.unwrap();

    // Two genuinely serialized 200ms waits take close to 400ms; a racy
    // limiter that lets both fire after a single shared wait finishes
    // close to 200ms. 350ms cleanly separates the two.
    assert!(start.elapsed() >= std::time::Duration::from_millis(350));
}

#[test]
fn header_lookup_is_case_insensitive() {
    let mut config = HttpClientConfig::default();
    config
        .headers
        .insert("Authorization".to_string(), "Bearer abc".to_string());
    let client = HttpClient::new("https://example.test", config);

    assert_eq!(client.header("authorization"), Some("Bearer abc"));
    assert_eq!(client.header("AUTHORIZATION"), Some("Bearer abc"));
    assert_eq!(client.header("Cookie"), None);
}

#[tokio::test]
async fn request_level_header_overrides_client_level_header_of_the_same_name() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("ok")).await;
    let mut config = HttpClientConfig::default();
    config
        .headers
        .insert("X-Foo".to_string(), "client-value".to_string());
    let client = HttpClient::new(base_url, config);

    client
        .request(HttpRequest::get().header("X-Foo", "req-value"))
        .await
        .unwrap();

    let recorded = rx.await.unwrap();
    let matches: Vec<_> = recorded
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-foo"))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one X-Foo header, got {matches:?}"
    );
    assert_eq!(matches[0].1, "req-value");
}

#[test]
fn headers_exposes_every_configured_client_header() {
    let mut config = HttpClientConfig::default();
    config
        .headers
        .insert("Authorization".to_string(), "Bearer abc".to_string());
    config
        .headers
        .insert("X-Test".to_string(), "abc".to_string());
    let client = HttpClient::new("https://example.test", config);

    let all = client.headers();
    assert_eq!(all.len(), 2);
    assert_eq!(
        all.get("Authorization").map(String::as_str),
        Some("Bearer abc")
    );
    assert_eq!(all.get("X-Test").map(String::as_str), Some("abc"));
}

#[tokio::test]
async fn raw_body_is_sent_verbatim_without_form_encoding() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("ok")).await;
    let client = HttpClient::new(base_url, HttpClientConfig::default());

    client
        .request(
            HttpRequest::post()
                .raw_body(b"<doc>&xxe;</doc>".to_vec())
                .header("Content-Type", "application/xml"),
        )
        .await
        .unwrap();

    let recorded = rx.await.unwrap();
    assert_eq!(recorded.body, "<doc>&xxe;</doc>");
}

#[tokio::test]
async fn raw_body_is_ignored_when_json_is_also_set() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("ok")).await;
    let client = HttpClient::new(base_url, HttpClientConfig::default());

    client
        .request(
            HttpRequest::post()
                .json(serde_json::json!({"a": 1}))
                .raw_body(b"ignored".to_vec()),
        )
        .await
        .unwrap();

    let recorded = rx.await.unwrap();
    assert_eq!(recorded.body, r#"{"a":1}"#);
}

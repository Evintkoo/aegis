mod support;

use pentest_core::{HttpClient, HttpClientConfig, HttpRequest};
use support::{one_shot_server, TestResponse};

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
    assert!(!recorded.path_and_query.contains("id=1&") && !recorded.path_and_query.ends_with("id=1"));
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
    config.headers.insert("X-Test".to_string(), "abc".to_string());
    let client = HttpClient::new(base_url, config);

    client.request(HttpRequest::get()).await.unwrap();

    let recorded = rx.await.unwrap();
    assert!(recorded.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-test") && v == "abc"));
}

#[tokio::test]
async fn first_request_on_a_fresh_client_is_not_delayed() {
    let (base_url, rx) = one_shot_server(TestResponse::ok("one")).await;
    let config = HttpClientConfig { delay: std::time::Duration::from_millis(300), ..HttpClientConfig::default() };
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

    let config = HttpClientConfig { delay: std::time::Duration::from_millis(200), ..HttpClientConfig::default() };
    let client = HttpClient::new(base_url_a.clone(), config);

    let start = std::time::Instant::now();
    client.request(HttpRequest::get()).await.unwrap();
    let _ = rx_a.await.unwrap();

    // Same client, different URL per-request (base_url is just the default) — the rate
    // limit lives on the client, not on any particular target URL.
    client.request(HttpRequest::get().url(base_url_b)).await.unwrap();
    let _ = rx_b.await.unwrap();

    assert!(start.elapsed() >= std::time::Duration::from_millis(200));
}

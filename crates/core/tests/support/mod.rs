use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct TestResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl TestResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Starts a one-shot HTTP/1.1 server on 127.0.0.1 that answers exactly one
/// request with `response`, then returns what it received. Returns the
/// base URL to hit and a receiver for the captured request.
pub async fn one_shot_server(
    response: TestResponse,
) -> (String, tokio::sync::oneshot::Receiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = socket.read(&mut buf).await.unwrap();
        let request_text = String::from_utf8_lossy(&buf[..n]).to_string();
        let recorded = parse_request(&request_text);

        let mut raw = format!("HTTP/1.1 {} X\r\n", response.status);
        for (k, v) in &response.headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str(&format!(
            "Content-Length: {}\r\n\r\n{}",
            response.body.len(),
            response.body
        ));
        let _ = socket.write_all(raw.as_bytes()).await;
        let _ = tx.send(recorded);
    });

    (format!("http://{addr}"), rx)
}

fn parse_request(text: &str) -> RecordedRequest {
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path_and_query = parts.next().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            body.push_str(line);
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    RecordedRequest {
        method,
        path_and_query,
        headers,
        body,
    }
}

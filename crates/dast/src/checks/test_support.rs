#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub struct ScriptedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub delay_ms: u64,
}

impl ScriptedResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: body.into(),
            delay_ms: 0,
        }
    }

    pub fn with_status(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![],
            body: body.into(),
            delay_ms: 0,
        }
    }

    pub fn delayed(body: impl Into<String>, delay_ms: u64) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: body.into(),
            delay_ms,
        }
    }

    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

/// `handler` receives the parsed request and this server's own base URL
/// (`http://127.0.0.1:<port>`, known only after binding) -- needed by
/// tests where a scripted response must self-reference the server's own
/// origin (e.g. a sitemap.xml `<loc>` entry, which must be absolute).
pub async fn scripted_server<F>(handler: F) -> String
where
    F: Fn(&RecordedRequest, &str) -> ScriptedResponse + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let handler = Arc::new(handler);
    let base_for_handler = base.clone();

    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let handler = Arc::clone(&handler);
            let base = base_for_handler.clone();
            tokio::spawn(handle_one(socket, handler, base));
        }
    });

    base
}

async fn handle_one<F>(mut socket: tokio::net::TcpStream, handler: Arc<F>, base: String)
where
    F: Fn(&RecordedRequest, &str) -> ScriptedResponse + Send + Sync + 'static,
{
    let mut buf = vec![0u8; 65536];
    let Ok(n) = socket.read(&mut buf).await else {
        return;
    };
    if n == 0 {
        return;
    }
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let recorded = parse_request(&text);
    let response = handler(&recorded, &base);

    if response.delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(response.delay_ms)).await;
    }

    let mut raw = format!("HTTP/1.1 {} X\r\n", response.status);
    for (k, v) in &response.headers {
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    raw.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.body.len(),
        response.body
    ));
    let _ = socket.write_all(raw.as_bytes()).await;
}

fn parse_request(text: &str) -> RecordedRequest {
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or("GET");
    let path_and_query = parts.next().unwrap_or("/").to_string();
    let (path, query_str) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query.as_str(), ""));
    let query = query_str
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (urldecode(k), urldecode(v))
        })
        .collect();

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
        path: path.to_string(),
        query,
        headers,
        body,
    }
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

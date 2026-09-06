//! Minimal out-of-band (OOB) interaction listener. Port of `collaborator.py`.
//!
//! Run this on a host the TARGET server can reach. Any HTTP request it
//! receives is logged and bucketed by a token embedded in the path
//! (`/<token>/...`). Blind-vuln payloads point the target at
//! `http://<this-host>:<port>/<token>/...` -- when the target's server (or
//! a victim's browser, for blind XSS) fetches that URL, the hit lands here
//! and confirms the vulnerability.
//!
//! Query hits programmatically: `GET /__hits/<token>` -> JSON list (not
//! logged as a hit itself). A lightweight, self-hosted alternative to Burp
//! Collaborator -- HTTP only, no DNS. Only expose it on infrastructure you
//! control.
//!
//! Deviation from the Python original: `collaborator.py`'s
//! `BaseHTTPRequestHandler` only defines handlers for GET/POST/PUT/HEAD/
//! OPTIONS (any other verb gets a generic 501 from the stdlib). This port
//! records a hit for ANY method -- an OOB catcher only benefits from
//! seeing an interaction sent via an unusual verb; there's no
//! correctness or security reason to reject one. Disclosed, deliberate,
//! and strictly more permissive than the original.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub ts: f64,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub client: String,
}

pub struct Collaborator {
    hits: Mutex<HashMap<String, Vec<Hit>>>,
    start: Instant,
}

impl Default for Collaborator {
    fn default() -> Self {
        Self::new()
    }
}

impl Collaborator {
    pub fn new() -> Self {
        Self { hits: Mutex::new(HashMap::new()), start: Instant::now() }
    }

    /// Hits recorded so far for `token`, most-recent-last -- exposed for
    /// tests and for in-process embedding; the network protocol is
    /// `GET /__hits/<token>` (see [`crate::client::get_hits`]).
    pub fn hits_for(&self, token: &str) -> Vec<Hit> {
        self.hits.lock().unwrap().get(token).cloned().unwrap_or_default()
    }

    /// Accepts connections from `listener` forever, one spawned task per
    /// connection. Never returns under normal operation -- callers that
    /// need to stop it race this against a cancellation future (the
    /// `collaborator` binary races it against `tokio::signal::ctrl_c()`).
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((socket, peer)) = listener.accept().await else { continue };
            let this = Arc::clone(&self);
            tokio::spawn(async move { this.handle_conn(socket, peer).await });
        }
    }

    async fn handle_conn(&self, mut socket: tokio::net::TcpStream, peer: SocketAddr) {
        let mut buf = vec![0u8; 65536];
        let Ok(n) = socket.read(&mut buf).await else { return };
        if n == 0 {
            return;
        }
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        let Some((method, path, headers)) = parse_request(&text) else { return };

        if let Some(token) = path.strip_prefix("/__hits/") {
            let token = token.trim_matches('/');
            let hits = self.hits_for(token);
            let body = serde_json::to_vec(&hits).unwrap_or_else(|_| b"[]".to_vec());
            let mut raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ".to_vec();
            raw.extend_from_slice(body.len().to_string().as_bytes());
            raw.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
            raw.extend_from_slice(&body);
            let _ = socket.write_all(&raw).await;
            return;
        }

        let seg = path.trim_start_matches('/').split('/').next().unwrap_or("").split('?').next().unwrap_or("");
        let token = if seg.is_empty() { "_".to_string() } else { seg.to_string() };
        let hit = Hit {
            ts: self.start.elapsed().as_secs_f64(),
            method: method.clone(),
            path: path.clone(),
            headers,
            client: peer.ip().to_string(),
        };
        self.hits.lock().unwrap().entry(token.clone()).or_default().push(hit);
        println!("[OOB HIT] token={token} {method} {path} from {}", peer.ip());

        let body = b"ok";
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nok", body.len());
        let _ = socket.write_all(raw.as_bytes()).await;
    }
}

/// Binds `host:port` and returns the listener plus its bound address (the
/// caller learns the real port when `port == 0`, as tests do).
pub async fn bind(host: &str, port: u16) -> std::io::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind((host, port)).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

fn parse_request(text: &str) -> Option<(String, String, HashMap<String, String>)> {
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Some((method, path, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_test_server() -> (Arc<Collaborator>, String) {
        let (listener, addr) = bind("127.0.0.1", 0).await.unwrap();
        let collab = Arc::new(Collaborator::new());
        tokio::spawn(Arc::clone(&collab).serve(listener));
        (collab, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn records_a_hit_bucketed_by_the_first_path_segment() {
        let (collab, base) = spawn_test_server().await;
        let client = reqwest::Client::new();
        client.get(format!("{base}/tok123/ssrf")).send().await.unwrap();

        // The handler runs in a spawned task; give it a moment to land.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let hits = collab.hits_for("tok123");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].method, "GET");
        assert_eq!(hits[0].path, "/tok123/ssrf");
        assert_eq!(hits[0].client, "127.0.0.1");
    }

    #[tokio::test]
    async fn hits_endpoint_returns_json_without_recording_itself_as_a_hit() {
        let (collab, base) = spawn_test_server().await;
        let client = reqwest::Client::new();
        client.get(format!("{base}/tok456/x")).send().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let resp = client.get(format!("{base}/__hits/tok456")).send().await.unwrap();
        let hits: Vec<Hit> = resp.json().await.unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/tok456/x");
        // The control-endpoint request itself must not be bucketed under
        // "__hits" (or anything else) as a second hit.
        assert!(collab.hits_for("__hits").is_empty());
    }

    #[tokio::test]
    async fn unknown_token_returns_an_empty_list_not_an_error() {
        let (_collab, base) = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client.get(format!("{base}/__hits/never-seen")).send().await.unwrap();
        let hits: Vec<Hit> = resp.json().await.unwrap();
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn missing_path_segment_buckets_under_underscore() {
        let (collab, base) = spawn_test_server().await;
        let client = reqwest::Client::new();
        client.get(format!("{base}/")).send().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(collab.hits_for("_").len(), 1);
    }

    #[tokio::test]
    async fn strips_a_trailing_query_string_from_the_bucketing_token() {
        let (collab, base) = spawn_test_server().await;
        let client = reqwest::Client::new();
        client.get(format!("{base}/abc123?cachebust=1")).send().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let hits = collab.hits_for("abc123");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/abc123?cachebust=1"); // full path is still recorded verbatim on the Hit
    }
}

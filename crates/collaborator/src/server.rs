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
//! Hits are also persisted, best-effort, as JSON lines (one `Hit` per
//! line) to `collaborator-hits.jsonl` in the working directory -- a
//! durable trail of interactions that survives restarts. The log is
//! write-only for now: `GET /__hits/<token>` still serves from memory,
//! nothing is replayed on startup.
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

/// Where hits are persisted (in the working directory the server runs
/// in). Override per-instance with [`Collaborator::with_hit_log_path`].
const HIT_LOG_FILE: &str = "collaborator-hits.jsonl";

/// Hard cap on how many bytes of one request are read before giving up.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

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
    log_path: std::path::PathBuf,
}

impl Default for Collaborator {
    fn default() -> Self {
        Self::new()
    }
}

impl Collaborator {
    pub fn new() -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            start: Instant::now(),
            log_path: std::path::PathBuf::from(HIT_LOG_FILE),
        }
    }

    /// Overrides where hits are persisted (tests point this at a temp
    /// file so runs don't leave a `collaborator-hits.jsonl` behind).
    pub fn with_hit_log_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.log_path = path.into();
        self
    }

    /// Hits recorded so far for `token`, most-recent-last -- exposed for
    /// tests and for in-process embedding; the network protocol is
    /// `GET /__hits/<token>` (see [`crate::client::get_hits`]).
    pub fn hits_for(&self, token: &str) -> Vec<Hit> {
        self.hits
            .lock()
            .unwrap()
            .get(token)
            .cloned()
            .unwrap_or_default()
    }

    /// Accepts connections from `listener` forever, one spawned task per
    /// connection. Never returns under normal operation -- callers that
    /// need to stop it race this against a cancellation future (the
    /// `collaborator` binary races it against `tokio::signal::ctrl_c()`).
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((socket, peer)) = listener.accept().await else {
                continue;
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move { this.handle_conn(socket, peer).await });
        }
    }

    /// Best-effort JSON-lines persistence: appends one serialized `Hit`
    /// per line to `self.log_path`. Write-only -- `GET /__hits/<token>`
    /// still serves from memory (see the module docs).
    fn append_hit_log(&self, hit: &Hit) {
        if let Ok(mut line) = serde_json::to_string(hit) {
            line.push('\n');
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
        }
    }
}

/// Reads one full HTTP request off `socket`: loops until the header
/// terminator (`\r\n\r\n`) has arrived, then keeps reading until
/// `Content-Length` body bytes are in. A single `read()` returns whatever
/// TCP has delivered so far -- headers and body routinely split across
/// segments -- which used to truncate (and so lose) such hits. Returns
/// `None` when nothing parseable arrived or the 1MB cap is exceeded;
/// on EOF with partial data it returns what it has, lenient like the
/// old single-read path.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut data: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        if let Some(head_end) = find(&data, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..head_end]);
            let body_len = data.len().saturating_sub(head_end + 4);
            if body_len >= content_length(&head) {
                return Some(String::from_utf8_lossy(&data).to_string());
            }
        }
        if data.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return if data.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&data).to_string())
            };
        }
        data.extend_from_slice(&chunk[..n]);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// `Content-Length` from a raw header block, defaulting to 0 (GETs carry
/// none); unparseable values are treated the same.
fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

impl Collaborator {
    async fn handle_conn(&self, mut socket: tokio::net::TcpStream, peer: SocketAddr) {
        let Some(text) = read_request(&mut socket).await else {
            return;
        };
        let Some((method, path, headers)) = parse_request(&text) else {
            return;
        };

        if let Some(token) = path.strip_prefix("/__hits/") {
            let token = token.trim_matches('/');
            let hits = self.hits_for(token);
            let body = serde_json::to_vec(&hits).unwrap_or_else(|_| b"[]".to_vec());
            let mut raw =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ".to_vec();
            raw.extend_from_slice(body.len().to_string().as_bytes());
            raw.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
            raw.extend_from_slice(&body);
            let _ = socket.write_all(&raw).await;
            return;
        }

        let seg = path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("");
        let token = if seg.is_empty() {
            "_".to_string()
        } else {
            seg.to_string()
        };
        let hit = Hit {
            ts: self.start.elapsed().as_secs_f64(),
            method: method.clone(),
            path: path.clone(),
            headers,
            client: peer.ip().to_string(),
        };
        self.hits
            .lock()
            .unwrap()
            .entry(token.clone())
            .or_default()
            .push(hit.clone());
        self.append_hit_log(&hit);
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

    /// Each test gets its own temp log path so a run never leaves a
    /// `collaborator-hits.jsonl` behind in the crate directory.
    fn unique_log_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pentest-collab-hits-{}-{tag}.jsonl",
            std::process::id()
        ))
    }

    async fn spawn_test_server() -> (Arc<Collaborator>, String) {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let tag = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (listener, addr) = bind("127.0.0.1", 0).await.unwrap();
        let collab =
            Arc::new(Collaborator::new().with_hit_log_path(unique_log_path(&tag.to_string())));
        tokio::spawn(Arc::clone(&collab).serve(listener));
        (collab, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn records_a_hit_bucketed_by_the_first_path_segment() {
        let (collab, base) = spawn_test_server().await;
        let client = reqwest::Client::new();
        client
            .get(format!("{base}/tok123/ssrf"))
            .send()
            .await
            .unwrap();

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

        let resp = client
            .get(format!("{base}/__hits/tok456"))
            .send()
            .await
            .unwrap();
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
        let resp = client
            .get(format!("{base}/__hits/never-seen"))
            .send()
            .await
            .unwrap();
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
        client
            .get(format!("{base}/abc123?cachebust=1"))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let hits = collab.hits_for("abc123");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/abc123?cachebust=1"); // full path is still recorded verbatim on the Hit
    }

    /// A request whose headers and body arrive in separate TCP segments
    /// (and whose body itself is split) must be assembled whole before
    /// the hit is recorded -- the old single `read()` truncated it.
    #[tokio::test]
    async fn assembles_a_request_split_across_tcp_segments() {
        let (collab, base) = spawn_test_server().await;
        let mut sock = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
            .await
            .unwrap();
        sock.write_all(b"POST /split9/x HTTP/1.1\r\nHost: t\r\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        sock.write_all(b"Content-Length: 5\r\n\r\nhel")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        sock.write_all(b"lo").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let hits = collab.hits_for("split9");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].method, "POST");
        assert_eq!(hits[0].path, "/split9/x");
    }

    #[tokio::test]
    async fn appends_each_hit_to_the_jsonl_log() {
        let log = unique_log_path("logtest");
        let _ = std::fs::remove_file(&log);
        let (listener, addr) = bind("127.0.0.1", 0).await.unwrap();
        let collab = Arc::new(Collaborator::new().with_hit_log_path(&log));
        tokio::spawn(Arc::clone(&collab).serve(listener));

        let client = reqwest::Client::new();
        client
            .get(format!("http://{addr}/logtok/h"))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let hit: Hit = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(hit.path, "/logtok/h");
        assert_eq!(hit.client, "127.0.0.1");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn content_length_parses_case_insensitively_and_defaults_to_zero() {
        assert_eq!(content_length("POST /x HTTP/1.1\r\nhost: t"), 0);
        assert_eq!(content_length("POST /x HTTP/1.1\r\nContent-Length: 42"), 42);
        assert_eq!(content_length("POST /x HTTP/1.1\r\ncontent-length: 7"), 7);
        assert_eq!(
            content_length("POST /x HTTP/1.1\r\nContent-Length: junk"),
            0
        );
    }
}

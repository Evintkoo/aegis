use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::FromDer;

pub const NAME: &str = "recon";

const FINGERPRINT_HEADERS: &[&str] = &[
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via",
];
const RISKY_METHODS: &[&str] = &["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(r) = client.request(HttpRequest::get()).await else {
        return out;
    };

    for h in FINGERPRINT_HEADERS {
        if let Some(v) = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(h)) {
            out.push(
                Finding::new(NAME, Severity::Info, format!("{h} header exposed"), "reveals stack/version to attackers")
                    .with_evidence(v.1.clone()),
            );
        }
    }

    if let Ok(opt) = client.request(HttpRequest { method: reqwest_method_options(), ..HttpRequest::get() }).await {
        if let Some((_, allow)) = opt.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Allow")) {
            let risky: Vec<&str> = RISKY_METHODS.iter().filter(|m| allow.to_uppercase().contains(*m)).copied().collect();
            let sev = if risky.is_empty() { Severity::Info } else { Severity::Medium };
            let detail = if risky.is_empty() {
                format!("OPTIONS advertises: {allow}")
            } else {
                format!("OPTIONS advertises: {allow} — risky: {risky:?}")
            };
            out.push(Finding::new(NAME, sev, "Allowed HTTP methods", detail).with_evidence(allow.clone()));
        }
    }

    if let Some(host) = extract_host(client.base_url()) {
        // `inspect_tls` does blocking socket I/O (a synchronous TCP connect plus a
        // blocking rustls handshake loop) — running it directly on the async executor
        // would risk stalling other concurrent checks sharing the same Tokio worker
        // thread, so it's pushed onto Tokio's dedicated blocking thread pool. A `JoinError`
        // here (task panic) degrades to an Info finding rather than propagating a panic.
        let tls_result = tokio::task::spawn_blocking(move || inspect_tls(&host, 443))
            .await
            .unwrap_or_else(|e| Err(format!("TLS inspection task panicked: {e}")));
        match tls_result {
            Ok((version, not_after, subject)) => {
                // `rustls::ProtocolVersion`'s `{:?}` Debug output uses the enum's actual
                // variant names (e.g. "TLSv1_3", "TLSv1_0", "SSLv3"), verified live against
                // a real handshake — not the dotted "TLSv1.0"/"TLSv1.1" form.
                let weak = matches!(version.as_str(), "TLSv1_0" | "TLSv1_1" | "SSLv3" | "SSLv2");
                let sev = if weak { Severity::Medium } else { Severity::Info };
                let title = if weak { "Weak TLS version negotiated" } else { "TLS version" };
                out.push(Finding::new(NAME, sev, title, format!("negotiated {version}")).with_evidence(version.clone()));
                out.push(
                    Finding::new(NAME, Severity::Info, "TLS certificate", format!("expires {not_after}"))
                        .with_evidence(subject),
                );
            }
            Err(e) => {
                out.push(Finding::new(NAME, Severity::Info, "TLS inspection failed", e));
            }
        }
    }

    out
}

fn reqwest_method_options() -> reqwest::Method {
    reqwest::Method::OPTIONS
}

fn extract_host(base_url: &str) -> Option<String> {
    let without_scheme = base_url.split("://").nth(1)?;
    let host_port = without_scheme.split('/').next()?;
    if !base_url.starts_with("https://") {
        return None;
    }
    Some(host_port.split(':').next()?.to_string())
}

/// Performs a raw TLS handshake against `host:port` directly via `rustls` (not
/// `reqwest`, which doesn't expose the negotiated protocol version or peer
/// certificate), returning `(protocol_version, cert_not_after, cert_subject)`.
///
/// This function does blocking I/O end-to-end (a synchronous `connect_timeout` plus a
/// blocking read/write handshake loop) — callers must run it via
/// `tokio::task::spawn_blocking`, not directly on an async executor.
///
/// ### Weak-TLS-version detection is effectively unreachable against real servers
///
/// `rustls`'s client deliberately does not implement TLS 1.0, TLS 1.1, or SSLv3/SSLv2
/// at all (per rustls's own documentation, it speaks only TLS 1.2 and 1.3) — this is
/// not a default that can be misconfigured, it's simply absent from the protocol
/// state machine. A server that only offers a legacy protocol therefore cannot be
/// "negotiated down to" here: the handshake fails outright (surfaced by the caller as
/// a generic Info-severity "TLS inspection failed" finding), rather than succeeding
/// with a legacy `protocol_version()` that would trip the "Weak TLS version
/// negotiated" Medium-severity match arm below. That arm is kept for
/// defense-in-depth (e.g. a future rustls version, or a different `ClientConfig`,
/// that does support negotiating legacy versions) but should not be relied on to
/// flag legacy-TLS-only targets today. This differs from Python's OpenSSL-backed
/// `ssl` module, which even in modern versions can still be forced to negotiate a
/// legacy protocol purely for detection purposes — there is no equivalent escape
/// hatch in `rustls`.
fn inspect_tls(host: &str, port: u16) -> Result<(String, String, String), String> {
    let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid hostname: {e}"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;

    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .next()
        .ok_or_else(|| format!("no addresses found for {host}"))?;
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("TCP connect failed: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(10))).ok();

    while conn.is_handshaking() {
        if conn.wants_write() {
            conn.write_tls(&mut sock).map_err(|e| format!("TLS write failed: {e}"))?;
        }
        if conn.wants_read() {
            conn.read_tls(&mut sock).map_err(|e| format!("TLS read failed: {e}"))?;
            conn.process_new_packets().map_err(|e| format!("TLS handshake failed: {e}"))?;
        }
    }

    let version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string());

    let certs = conn.peer_certificates().ok_or_else(|| "no peer certificate presented".to_string())?;
    let leaf = certs.first().ok_or_else(|| "empty certificate chain".to_string())?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| format!("certificate parse failed: {e}"))?;
    let not_after = parsed.tbs_certificate.validity.not_after.to_string();
    let subject = parsed.subject().to_string();

    Ok((version, not_after, subject))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_reads_hostname_from_https_url() {
        assert_eq!(extract_host("https://example.test:443/path"), Some("example.test".to_string()));
        assert_eq!(extract_host("https://example.test/path"), Some("example.test".to_string()));
    }

    #[test]
    fn extract_host_returns_none_for_http() {
        assert_eq!(extract_host("http://example.test/path"), None);
    }

    // Regression test for the connect timeout: 10.255.255.1 is a private (RFC 1918),
    // non-routable address, so `to_socket_addrs` resolves it locally (no real DNS
    // lookup) and the subsequent `connect_timeout` either fails fast (network
    // unreachable) or, if silently black-holed by the local network stack, is
    // bounded by the 10s timeout instead of hanging indefinitely on the bare
    // `TcpStream::connect` this replaced. Either way the call must return well
    // inside the timeout window, not hang.
    #[test]
    fn inspect_tls_bounds_a_hanging_connect_with_the_configured_timeout() {
        let start = std::time::Instant::now();
        let result = inspect_tls("10.255.255.1", 443);
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected the non-routable address to fail, got {result:?}");
        assert!(
            elapsed < Duration::from_secs(15),
            "connect_timeout did not bound the call: took {elapsed:?}"
        );
    }
}

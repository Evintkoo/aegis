use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};
use std::net::TcpStream;
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
        match inspect_tls(&host, 443) {
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

fn inspect_tls(host: &str, port: u16) -> Result<(String, String, String), String> {
    let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid hostname: {e}"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let mut sock = TcpStream::connect((host, port)).map_err(|e| format!("TCP connect failed: {e}"))?;
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
}

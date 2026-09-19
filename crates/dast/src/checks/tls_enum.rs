//! tls_enum — TLS protocol-version enumeration, opt-in via `--tls-enum`.
//!
//! Sends one minimal, well-formed TLS `ClientHello` per protocol version
//! (TLS 1.0, 1.1, 1.2, 1.3) over a raw socket and classifies the server's
//! first response record: a `ServerHello`/`HelloRetryRequest` means the
//! server accepted that version; an alert or a closed connection means it
//! rejected it. This is the same read-only probe technique `sslscan` and
//! `testssl.sh` use — nothing is authenticated, no session is completed,
//! and each socket is closed immediately after one response.
//!
//! https targets only (the raw-socket path carries no TLS client state),
//! never runs unless `--tls-enum` is passed. A summary `info` finding is
//! emitted whenever the server answered at least one probe; accepting
//! TLS 1.0/1.1 additionally raises a `high` finding, as both protocols
//! are deprecated (RFC 8996) and PCI DSS forbids them.

use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, Severity};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NAME: &str = "tls_enum";

const TIMEOUT: Duration = Duration::from_secs(3);

/// A deterministic 32-byte "random" field. Probe reproducibility beats
/// entropy here: nothing downstream consumes the ClientHello random, and
/// a fixed value keeps repeated scans byte-identical.
const HELLO_RANDOM: [u8; 32] = [0xAA; 32];

/// Deterministic x25519 "public key" for the TLS 1.3 key_share. The
/// handshake is never completed, so the shared secret is never used;
/// the bytes only need to be well-formed.
const HELLO_KEY_SHARE: [u8; 32] = [0x42; 32];

/// Classic suites every TLS 1.0-1.2 server that is not purposefully
/// broken will recognize: TLS_RSA_WITH_AES_128_CBC_SHA,
/// TLS_RSA_WITH_AES_256_CBC_SHA.
const LEGACY_SUITES: [u16; 2] = [0x002F, 0x0035];

/// TLS_AES_128_GCM_SHA256 — the mandatory-to-implement TLS 1.3 suite.
const TLS13_SUITES: [u16; 1] = [0x1301];

/// Outcome of one version probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Accepted,
    Rejected,
}

/// Classifies the first response bytes to a ClientHello: any ServerHello
/// (record type 22, handshake type 2 — HelloRetryRequest included, which
/// itself proves TLS 1.3 support) means the version was accepted; an
/// alert, garbage, or an empty/closed read means it was rejected.
/// Exposed for testing.
pub fn classify_hello_response(first_read: &[u8]) -> Probe {
    if first_read.len() >= 6 && first_read[0] == 22 && first_read[5] == 2 {
        Probe::Accepted
    } else {
        Probe::Rejected
    }
}

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// Builds one TLS record wrapping a single ClientHello handshake message.
/// Exposed for testing.
pub fn client_hello_record(
    client_version: [u8; 2],
    cipher_suites: &[u16],
    extensions: &[u8],
) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(2 + 32 + 1 + 2 + cipher_suites.len() * 2 + 2 + 2 + extensions.len());
    body.extend_from_slice(&client_version);
    body.extend_from_slice(&HELLO_RANDOM);
    body.push(0); // empty session id
    body.extend_from_slice(&u16b((cipher_suites.len() * 2) as u16));
    for suite in cipher_suites {
        body.extend_from_slice(&u16b(*suite));
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression: null only
    body.extend_from_slice(&u16b(extensions.len() as u16));
    body.extend_from_slice(extensions);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(0x01); // ClientHello
    let len = body.len();
    hello.extend_from_slice(&u24b(len as u32));
    hello.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake record, legacy record version
    record.extend_from_slice(&u16b(hello.len() as u16));
    record.extend_from_slice(&hello);
    record
}

fn u24b(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

fn extension(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut e = u16b(ty).to_vec();
    e.extend_from_slice(&u16b(data.len() as u16));
    e.extend_from_slice(data);
    e
}

/// ClientHello for TLS 1.0-1.2 probes (server picks its highest supported
/// version <= client_version, per RFC 5246 §E.1).
fn legacy_hello(client_version: [u8; 2]) -> Vec<u8> {
    client_hello_record(client_version, &LEGACY_SUITES, &[])
}

/// ClientHello for the TLS 1.3 probe: client_version stays 0x0303 (the
/// middlebox-compatibility form) with TLS 1.3 negotiated via the
/// supported_versions extension, plus the signature_algorithms,
/// supported_groups, and key_share extensions a 1.3 server requires.
fn tls13_hello() -> Vec<u8> {
    let supported_versions = extension(0x002B, &[0x02, 0x03, 0x04]);
    let signature_algorithms = extension(0x000D, &[0x00, 0x02, 0x08, 0x04]);
    let supported_groups = extension(0x000A, &[0x00, 0x02, 0x00, 0x1D]);
    let mut share = vec![0x00, 0x1D, 0x00, 0x20];
    share.extend_from_slice(&HELLO_KEY_SHARE);
    // key_share extension data is a list: u16 length prefix + one entry
    let mut share_list = u16b(share.len() as u16).to_vec();
    share_list.extend_from_slice(&share);
    let key_share = extension(0x0033, &share_list);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&supported_versions);
    extensions.extend_from_slice(&signature_algorithms);
    extensions.extend_from_slice(&supported_groups);
    extensions.extend_from_slice(&key_share);
    client_hello_record([0x03, 0x03], &TLS13_SUITES, &extensions)
}

async fn raw_probe(addr: &str, request: &[u8]) -> Option<Probe> {
    let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let _ = stream.write_all(request).await;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(classify_hello_response(&buf[..n]))
}

fn https_host_port(base_url: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(base_url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?.to_string();
    Some((host, url.port_or_known_default()?))
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    if !opts.tls_enum {
        return Vec::new();
    }
    let Some((host, port)) = https_host_port(client.base_url()) else {
        return Vec::new();
    };
    let addr = format!("{host}:{port}");

    let versions: [(&str, Vec<u8>); 4] = [
        ("TLS1.0", legacy_hello([0x03, 0x01])),
        ("TLS1.1", legacy_hello([0x03, 0x02])),
        ("TLS1.2", legacy_hello([0x03, 0x03])),
        ("TLS1.3", tls13_hello()),
    ];

    let mut answered = false;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for (label, hello) in &versions {
        match raw_probe(&addr, hello).await {
            Some(Probe::Accepted) => {
                answered = true;
                accepted.push(*label);
            }
            Some(Probe::Rejected) => {
                answered = true;
                rejected.push(*label);
            }
            None => {}
        }
    }
    if !answered {
        return Vec::new();
    }

    let mut out = Vec::new();
    let legacy: Vec<&str> = accepted
        .iter()
        .copied()
        .filter(|v| *v == "TLS1.0" || *v == "TLS1.1")
        .collect();
    if !legacy.is_empty() {
        out.push(
            Finding::new(
                NAME,
                Severity::High,
                "Server accepts deprecated TLS versions",
                format!(
                    "{} negotiated a ServerHello — deprecated per RFC 8996 and rejected by PCI DSS; disable {} server-side",
                    legacy.join(" and "),
                    legacy.join("/")
                ),
            )
            .with_evidence(format!("accepted={}", legacy.join(","))),
        );
    }
    out.push(
        Finding::new(
            NAME,
            Severity::Info,
            "TLS version support enumerated",
            format!(
                "accepted: {}; rejected: {} (direct ClientHello probes against {addr})",
                if accepted.is_empty() {
                    "none".to_string()
                } else {
                    accepted.join(", ")
                },
                if rejected.is_empty() {
                    "none".to_string()
                } else {
                    rejected.join(", ")
                }
            ),
        )
        .with_evidence(format!("accepted={:?} rejected={:?}", accepted, rejected)),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::ScriptedResponse;
    use pentest_core::HttpClientConfig;

    fn fast_client(base_url: String) -> HttpClient {
        HttpClient::new(
            base_url,
            HttpClientConfig {
                delay: std::time::Duration::from_millis(0),
                ..HttpClientConfig::default()
            },
        )
    }

    /// A minimal canned ServerHello record.
    fn server_hello_record() -> Vec<u8> {
        let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x2A, 0x02, 0x00, 0x00, 0x26];
        hello.extend_from_slice(&[0u8; 40]);
        hello
    }

    #[test]
    fn a_server_hello_is_accepted_and_an_alert_is_rejected() {
        let server_hello = server_hello_record();
        assert_eq!(classify_hello_response(&server_hello), Probe::Accepted);

        // alert record: record(21) ver(03 03) len(00 02) fatal(02) handshake_failure(28)
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(classify_hello_response(&alert), Probe::Rejected);
        assert_eq!(classify_hello_response(&[]), Probe::Rejected);
        assert_eq!(classify_hello_response(&[0x16, 0x03]), Probe::Rejected);
    }

    #[test]
    fn client_hello_records_are_structurally_consistent() {
        for (record, version) in [
            (legacy_hello([0x03, 0x01]), [0x03, 0x01]),
            (legacy_hello([0x03, 0x03]), [0x03, 0x03]),
            (tls13_hello(), [0x03, 0x03]),
        ] {
            assert_eq!(record[0], 0x16);
            let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
            assert_eq!(
                record_len + 5,
                record.len(),
                "record length must cover the hello"
            );
            assert_eq!(record[5], 0x01, "handshake type must be ClientHello");
            let hs_len =
                ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
            assert_eq!(
                hs_len + 4,
                record_len,
                "handshake length must cover the body"
            );
            // client_version sits right after the 4-byte handshake header
            assert_eq!(&record[9..11], &version);
            // extension block must parse cleanly to the end of the hello
            let body = &record[9 + 2 + 32 + 1..];
            let suites_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            let after_suites = &body[2 + suites_len..];
            let comp_len = after_suites[0] as usize;
            let exts = &after_suites[1 + comp_len..];
            let exts_len = u16::from_be_bytes([exts[0], exts[1]]) as usize;
            assert_eq!(
                exts_len + 2,
                exts.len(),
                "extension block must cover the hello tail"
            );
        }
    }

    #[tokio::test]
    async fn flags_a_legacy_accepting_tls_server() {
        // Raw TCP server answering every read with a ServerHello.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let canned = server_hello_record();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&canned).await;
            }
        });

        let client = fast_client(format!("https://{addr}"));
        let opts = Opts {
            tls_enum: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("deprecated TLS")),
            "a server accepting every version must raise the legacy finding, got {findings:?}"
        );
        assert!(findings.iter().any(|f| f.severity == Severity::Info));
    }

    #[tokio::test]
    async fn a_server_that_alerts_every_version_is_reported_as_all_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&alert).await;
            }
        });

        let client = fast_client(format!("https://{addr}"));
        let opts = Opts {
            tls_enum: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            !findings.iter().any(|f| f.severity == Severity::High),
            "an all-alerting server must not raise the legacy finding, got {findings:?}"
        );
        let summary = findings
            .iter()
            .find(|f| f.title.contains("TLS version support enumerated"))
            .expect("summary finding must exist when the server answers");
        assert!(summary.evidence.contains("accepted=[]"));
    }

    #[tokio::test]
    async fn a_server_that_closes_without_answering_counts_as_rejection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                drop(sock); // close without answering
            }
        });

        let client = fast_client(format!("https://{addr}"));
        let opts = Opts {
            tls_enum: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(
            !findings.iter().any(|f| f.severity == Severity::High),
            "a closing server must not raise the legacy finding, got {findings:?}"
        );
        let summary = findings
            .iter()
            .find(|f| f.title.contains("TLS version support enumerated"))
            .expect("summary finding must exist: EOF is a rejection, which is an answer");
        assert!(summary.evidence.contains("accepted=[]"));
    }

    #[tokio::test]
    async fn never_probes_without_the_opt_in_flag() {
        let base =
            crate::checks::test_support::scripted_server(|_req, _| ScriptedResponse::ok("ok"))
                .await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn skips_plain_http_targets() {
        let base =
            crate::checks::test_support::scripted_server(|_req, _| ScriptedResponse::ok("ok"))
                .await;
        let client = fast_client(base);
        let opts = Opts {
            tls_enum: true,
            ..Opts::default()
        };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.is_empty(), "http target -> no TLS probes");
    }
}

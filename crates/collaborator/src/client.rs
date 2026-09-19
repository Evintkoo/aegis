//! Client-side helper for polling a running collaborator for hits.
//! Polling policy (retry cadence, overall timeout) belongs to the caller
//! (`pentest-dast`'s `blind_oob` check) -- this is a single-shot fetch.

use crate::server::Hit;
use std::time::Duration;

#[derive(Debug)]
pub struct GetHitsError(pub String);

impl std::fmt::Display for GetHitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for GetHitsError {}

/// Fetches the hits recorded so far for `token` from a collaborator at
/// `collaborator_base` (e.g. `http://host:9000`). A network error or a
/// non-2xx response is surfaced as `Err` -- the caller treats that the
/// same as "no hits yet" and retries, matching the Python original's
/// blanket `except Exception: pass`.
pub async fn get_hits(collaborator_base: &str, token: &str) -> Result<Vec<Hit>, GetHitsError> {
    let url = format!("{}/__hits/{token}", collaborator_base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| GetHitsError(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(GetHitsError(format!("HTTP {}", resp.status())));
    }
    resp.json().await.map_err(|e| GetHitsError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{bind, Collaborator};
    use std::sync::Arc;

    #[tokio::test]
    async fn fetches_hits_recorded_by_a_real_server() {
        let (listener, addr) = bind("127.0.0.1", 0).await.unwrap();
        let collab = Arc::new(Collaborator::new());
        tokio::spawn(Arc::clone(&collab).serve(listener));
        let base = format!("http://{addr}");

        reqwest::Client::new()
            .get(format!("{base}/plant1/ssrf"))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let hits = get_hits(&base, "plant1").await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/plant1/ssrf");
    }

    #[tokio::test]
    async fn errors_when_nothing_is_listening() {
        let result = get_hits("http://127.0.0.1:1", "whatever").await;
        assert!(result.is_err());
    }
}

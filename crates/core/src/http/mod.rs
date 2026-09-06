mod error;
mod request;
mod response;

pub use error::HttpError;
pub use request::HttpRequest;
pub use response::HttpResponse;

use reqwest::Url;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct HttpClientConfig {
    pub headers: HashMap<String, String>,
    pub delay: Duration,
    pub timeout: Duration,
    pub verify_tls: bool,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            headers: HashMap::new(),
            delay: Duration::from_millis(400),
            timeout: Duration::from_secs(20),
            verify_tls: true,
        }
    }
}

pub struct HttpClient {
    base_url: String,
    headers: HashMap<String, String>,
    delay: Duration,
    last: Mutex<Instant>,
    client_follow: reqwest::Client,
    client_no_follow: reqwest::Client,
}

impl HttpClient {
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns just `"{scheme}://{host}[:port]"` — no path or query —
    /// for building absolute request URLs against other paths on the
    /// same origin. Distinct from `base_url()`, which returns the raw
    /// configured URL as-is (path/query included, if any).
    pub fn base_url_root(&self) -> String {
        match reqwest::Url::parse(&self.base_url) {
            Ok(u) => format!("{}://{}", u.scheme(), u.authority()),
            Err(_) => self.base_url.clone(),
        }
    }

    pub fn new(base_url: impl Into<String>, config: HttpClientConfig) -> Self {
        Self {
            base_url: base_url.into(),
            headers: config.headers,
            delay: config.delay,
            last: Mutex::new(Instant::now() - config.delay),
            client_follow: build_reqwest_client(config.verify_tls, config.timeout, true),
            client_no_follow: build_reqwest_client(config.verify_tls, config.timeout, false),
        }
    }

    pub async fn request(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.rate_limit().await;
        let url = self.build_url(&req)?;
        let client = if req.allow_redirects {
            &self.client_follow
        } else {
            &self.client_no_follow
        };

        let mut builder = client.request(req.method.clone(), url);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        if let Some(json) = &req.json {
            builder = builder.json(json);
        } else if !req.form.is_empty() {
            builder = builder.form(&req.form);
        }

        let start = Instant::now();
        let resp = builder.send().await?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await?;
        let elapsed = start.elapsed();

        Ok(HttpResponse {
            status,
            headers,
            body,
            elapsed,
            url: final_url,
        })
    }

    fn build_url(&self, req: &HttpRequest) -> Result<Url, HttpError> {
        let base = req.url.clone().unwrap_or_else(|| self.base_url.clone());
        let mut url = Url::parse(&base)?;
        if !req.params.is_empty() {
            let mut merged: HashMap<String, String> = url.query_pairs().into_owned().collect();
            for (k, v) in &req.params {
                merged.insert(k.clone(), v.clone());
            }
            let mut qp = url.query_pairs_mut();
            qp.clear();
            for (k, v) in &merged {
                qp.append_pair(k, v);
            }
        }
        Ok(url)
    }

    async fn rate_limit(&self) {
        let mut last = self.last.lock().await;
        let elapsed = last.elapsed();
        if elapsed < self.delay {
            tokio::time::sleep(self.delay - elapsed).await;
        }
        *last = Instant::now();
    }
}

fn build_reqwest_client(verify_tls: bool, timeout: Duration, follow_redirects: bool) -> reqwest::Client {
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::default()
    } else {
        reqwest::redirect::Policy::none()
    };
    reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(!verify_tls)
        .redirect(redirect_policy)
        .build()
        .expect("static reqwest client configuration must build")
}

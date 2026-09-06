use reqwest::Method;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Option<String>,
    pub params: HashMap<String, String>,
    pub form: HashMap<String, String>,
    pub json: Option<serde_json::Value>,
    /// A literal request body sent as-is (no form-urlencoding, no JSON
    /// serialization). Needed by checks that must send a raw payload --
    /// an XML document (`xxe`), or arbitrary probe bytes
    /// (`method_tampering`'s PUT/method-override probes) -- matching the
    /// Python originals' `data=<bytes>` calls, which bypass `common.py`'s
    /// own form/JSON encoding the same way.
    pub raw_body: Option<Vec<u8>>,
    pub headers: HashMap<String, String>,
    pub allow_redirects: bool,
}

impl HttpRequest {
    pub fn get() -> Self {
        Self {
            method: Method::GET,
            url: None,
            params: HashMap::new(),
            form: HashMap::new(),
            json: None,
            raw_body: None,
            headers: HashMap::new(),
            allow_redirects: true,
        }
    }

    pub fn post() -> Self {
        Self {
            method: Method::POST,
            ..Self::get()
        }
    }

    pub fn url(mut self, u: impl Into<String>) -> Self {
        self.url = Some(u.into());
        self
    }

    pub fn param(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.params.insert(k.into(), v.into());
        self
    }

    pub fn form_field(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.form.insert(k.into(), v.into());
        self
    }

    pub fn json(mut self, v: serde_json::Value) -> Self {
        self.json = Some(v);
        self
    }

    pub fn raw_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.raw_body = Some(body.into());
        self
    }

    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }

    pub fn no_redirects(mut self) -> Self {
        self.allow_redirects = false;
        self
    }
}

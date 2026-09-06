use reqwest::Method;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Option<String>,
    pub params: HashMap<String, String>,
    pub form: HashMap<String, String>,
    pub json: Option<serde_json::Value>,
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

    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }

    pub fn no_redirects(mut self) -> Self {
        self.allow_redirects = false;
        self
    }
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub param: Option<String>,
    pub method: String,
    pub base_value: String,
    pub wordlist: Option<String>,
    pub sleep: u64,
    /// A URL you monitor, for out-of-band SSRF confirmation (`ssrf`).
    pub ssrf_callback: Option<String>,
    /// Base URL of a running `pentest-collaborator` listener, for blind
    /// SSRF/XSS confirmation (`blind_oob`).
    pub collaborator: Option<String>,
    /// Opt-in: also run installed sqlmap/nikto/nuclei (`external`).
    pub external: bool,
    /// Login endpoint; opt-in gate for `auth_bruteforce` (silent no-op
    /// unless this AND `auth_username` are both set).
    pub login_url: Option<String>,
    /// A username you own that exists, for the enumeration test.
    pub auth_username: Option<String>,
    pub user_field: String,
    pub pass_field: String,
    /// Send the login attempt as JSON instead of a form body.
    pub auth_json: bool,
    /// Bad-login attempts to send; hard-capped at 5 by `auth_bruteforce`
    /// regardless of this value, to avoid locking out the account.
    pub auth_attempts: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            param: None,
            method: "GET".to_string(),
            base_value: "1".to_string(),
            wordlist: None,
            sleep: 5,
            ssrf_callback: None,
            collaborator: None,
            external: false,
            login_url: None,
            auth_username: None,
            user_field: "username".to_string(),
            pass_field: "password".to_string(),
            auth_json: false,
            auth_attempts: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_python_toolkits_defaults() {
        let o = Opts::default();
        assert_eq!(o.method, "GET");
        assert_eq!(o.base_value, "1");
        assert_eq!(o.param, None);
        assert_eq!(o.wordlist, None);
        assert_eq!(o.sleep, 5);
        assert_eq!(o.ssrf_callback, None);
        assert_eq!(o.collaborator, None);
        assert!(!o.external);
        assert_eq!(o.login_url, None);
        assert_eq!(o.auth_username, None);
        assert_eq!(o.user_field, "username");
        assert_eq!(o.pass_field, "password");
        assert!(!o.auth_json);
        assert_eq!(o.auth_attempts, 4);
    }
}

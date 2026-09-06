#[derive(Debug, Clone)]
pub struct Opts {
    pub param: Option<String>,
    pub method: String,
    pub base_value: String,
    pub wordlist: Option<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            param: None,
            method: "GET".to_string(),
            base_value: "1".to_string(),
            wordlist: None,
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
    }
}

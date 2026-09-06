use std::fmt;

#[derive(Debug)]
pub enum HttpError {
    InvalidUrl(String),
    Request(String),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::InvalidUrl(s) => write!(f, "invalid URL: {s}"),
            HttpError::Request(s) => write!(f, "request failed: {s}"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<reqwest::Error> for HttpError {
    fn from(e: reqwest::Error) -> Self {
        HttpError::Request(e.to_string())
    }
}

impl From<url::ParseError> for HttpError {
    fn from(e: url::ParseError) -> Self {
        HttpError::InvalidUrl(e.to_string())
    }
}

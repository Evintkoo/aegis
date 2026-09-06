//! auth_bruteforce — user enumeration & missing rate-limit / lockout (opt-in).
//!
//! SAFETY: this never guesses real passwords (no wordlist). It only sends
//! a small, bounded number of *deliberately wrong* logins to observe the
//! app's behavior: user enumeration (does a valid username respond
//! differently from a bogus one?) and missing rate limiting / lockout (are
//! repeated bad logins throttled at all?).
//!
//! Opt-in: requires `opts.login_url` + `opts.auth_username`. Attempts are
//! capped at 5 to avoid locking out the account. Run only against your
//! own login. Port of `checks/auth_bruteforce.py`.

use crate::checks::similarity;
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, HttpResponse, Severity};
use std::sync::LazyLock;
use std::time::Duration;

pub const NAME: &str = "auth_bruteforce";

static LOCKOUT_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(too many|rate limit|locked|lockout|try again later|captcha|temporarily (disabled|blocked)|slow down|429)").unwrap());
static NOUSER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)(no such user|user (not found|does not exist)|unknown (user|account)|invalid username|account not found|email not (found|registered))").unwrap()
});

async fn login(client: &HttpClient, opts: &Opts, user: &str, pw: &str) -> Option<HttpResponse> {
    let url = opts.login_url.clone()?;
    let req = if opts.auth_json {
        let mut map = serde_json::Map::new();
        map.insert(opts.user_field.clone(), serde_json::Value::String(user.to_string()));
        map.insert(opts.pass_field.clone(), serde_json::Value::String(pw.to_string()));
        HttpRequest::post().url(url).json(serde_json::Value::Object(map))
    } else {
        HttpRequest::post().url(url).form_field(&opts.user_field, user).form_field(&opts.pass_field, pw)
    };
    client.request(req).await.ok()
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let (Some(_), Some(valid_user)) = (opts.login_url.clone(), opts.auth_username.clone()) else {
        return Vec::new(); // opt-in; silent when not configured
    };
    let mut out = Vec::new();
    let bogus_user = format!("zzq_nouser_9182_{}", valid_user.chars().take(4).collect::<String>());
    let wrong_pw = "definitely_wrong_pw_9182!";
    let attempts = opts.auth_attempts.min(5);

    // --- 1) User enumeration -------------------------------------------------
    let Some(r_valid) = login(client, opts, &valid_user, wrong_pw).await else { return out };
    let Some(r_bogus) = login(client, opts, &bogus_user, wrong_pw).await else { return out };

    if let Some(m) = NOUSER_RE.find(&r_bogus.body).filter(|_| !NOUSER_RE.is_match(&r_valid.body)) {
        out.push(
            Finding::new(
                NAME,
                Severity::Medium,
                "Username enumeration (distinct error message)",
                "bogus username yields a 'no such user' message that a valid username does not — attackers can enumerate accounts",
            )
            .with_evidence(m.as_str().to_string()),
        );
    } else if r_valid.status != r_bogus.status || similarity(&r_valid.body, &r_bogus.body) < 0.9 {
        out.push(
            Finding::new(
                NAME,
                Severity::Low,
                "Possible username enumeration (response differs)",
                format!(
                    "valid vs bogus username differ (HTTP {} vs {}, sim {:.2}) — verify",
                    r_valid.status,
                    r_bogus.status,
                    similarity(&r_valid.body, &r_bogus.body)
                ),
            )
            .with_evidence(format!("{}/{}", r_valid.status, r_bogus.status)),
        );
    } else if r_valid.elapsed > r_bogus.elapsed + Duration::from_millis(400) {
        out.push(
            Finding::new(
                NAME,
                Severity::Low,
                "Possible timing-based username enumeration",
                format!(
                    "valid username is slower ({:.2}s vs {:.2}s) — password hashing only runs for real users",
                    r_valid.elapsed.as_secs_f64(),
                    r_bogus.elapsed.as_secs_f64()
                ),
            )
            .with_evidence(format!("{:.2}s vs {:.2}s", r_valid.elapsed.as_secs_f64(), r_bogus.elapsed.as_secs_f64())),
        );
    }

    // --- 2) Missing rate limiting / lockout ----------------------------------
    let mut throttled = false;
    for i in 0..attempts {
        let Some(r) = login(client, opts, &valid_user, &format!("{wrong_pw}{i}")).await else { continue };
        if r.status == 429 || LOCKOUT_RE.is_match(&r.body) {
            throttled = true;
            break;
        }
    }
    if !throttled {
        out.push(
            Finding::new(
                NAME,
                Severity::Medium,
                "No rate limiting / account lockout on login",
                format!("{attempts} bad logins for '{valid_user}' were all accepted without a 429, CAPTCHA, or lockout — enables credential brute-forcing"),
            )
            .with_evidence(format!("{attempts} attempts, no throttle")),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::{scripted_server, ScriptedResponse};
    use pentest_core::HttpClientConfig;

    fn fast_client(base_url: String) -> HttpClient {
        HttpClient::new(base_url, HttpClientConfig { delay: std::time::Duration::from_millis(0), ..HttpClientConfig::default() })
    }

    #[tokio::test]
    async fn silent_no_op_when_not_opted_in() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("ok")).await;
        let client = fast_client(base);

        let findings = run_impl(&client, &Opts::default()).await;

        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn detects_enumeration_via_distinct_error_message() {
        let base = scripted_server(|req, _| {
            if req.body.contains("zzq_nouser_9182") {
                ScriptedResponse::ok("Error: no such user")
            } else {
                ScriptedResponse::ok("Error: invalid password")
            }
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { login_url: Some(format!("{}/login", client.base_url())), auth_username: Some("alice".to_string()), auth_attempts: 2, ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "Username enumeration (distinct error message)"));
    }

    #[tokio::test]
    async fn detects_missing_rate_limiting() {
        let base = scripted_server(|_req, _| ScriptedResponse::ok("invalid credentials")).await;
        let client = fast_client(base);
        let opts = Opts { login_url: Some(format!("{}/login", client.base_url())), auth_username: Some("alice".to_string()), auth_attempts: 3, ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(findings.iter().any(|f| f.title == "No rate limiting / account lockout on login" && f.evidence.contains("3 attempts")));
    }

    #[tokio::test]
    async fn no_lockout_finding_when_the_app_throttles() {
        let base = scripted_server(|_req, _| ScriptedResponse::with_status(429, "too many requests")).await;
        let client = fast_client(base);
        let opts = Opts { login_url: Some(format!("{}/login", client.base_url())), auth_username: Some("alice".to_string()), auth_attempts: 3, ..Opts::default() };

        let findings = run_impl(&client, &opts).await;

        assert!(!findings.iter().any(|f| f.title == "No rate limiting / account lockout on login"));
    }

    #[tokio::test]
    async fn attempts_are_hard_capped_at_five_even_if_more_are_requested() {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = count.clone();
        let base = scripted_server(move |_req, _| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ScriptedResponse::ok("invalid credentials")
        })
        .await;
        let client = fast_client(base);
        let opts = Opts { login_url: Some(format!("{}/login", client.base_url())), auth_username: Some("alice".to_string()), auth_attempts: 20, ..Opts::default() };

        run_impl(&client, &opts).await;

        // 2 (enumeration: valid + bogus) + 5 (capped bad-login attempts) = 7.
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 7);
    }
}

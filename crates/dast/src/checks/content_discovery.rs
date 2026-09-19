use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "content_discovery";

const DEFAULT_PATHS: &[&str] = &[
    "/admin",
    "/administrator",
    "/login",
    "/dashboard",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/metrics",
    "/health",
    "/status",
    "/debug",
    "/console",
    "/.git/",
    "/.svn/",
    "/backup",
    "/backups",
    "/old",
    "/dev",
    "/test",
    "/staging",
    "/config",
    "/uploads",
    "/private",
    "/internal",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
    "/wp-admin/",
    "/wp-login.php",
    "/phpmyadmin/",
    "/server-status",
    "/.env",
];

const SENSITIVE_MARKERS: &[&str] = &[
    "admin",
    "actuator",
    "env",
    ".git",
    "backup",
    "phpmyadmin",
    "swagger",
    "debug",
    "console",
    "config",
];

fn load_wordlist(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| format!("/{}", l.trim_start_matches('/')))
                .collect()
        })
        .unwrap_or_default()
}

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = client.base_url_root();

    let mut paths: Vec<String> = DEFAULT_PATHS.iter().map(|s| s.to_string()).collect();
    if let Some(wl) = &opts.wordlist {
        paths.extend(load_wordlist(wl));
    }

    let Ok(ctrl) = client
        .request(
            HttpRequest::get()
                .url(format!("{root}/zzq_definitely_missing_9182"))
                .no_redirects(),
        )
        .await
    else {
        return out;
    };
    let (ctrl_status, ctrl_len) = (ctrl.status, ctrl.body.len());

    for p in &paths {
        let Ok(r) = client
            .request(HttpRequest::get().url(format!("{root}{p}")).no_redirects())
            .await
        else {
            continue;
        };
        if r.status == 401 || r.status == 403 {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Info,
                    format!("Protected resource present: {p}"),
                    format!("HTTP {} — exists but access-controlled", r.status),
                )
                .with_evidence(p.clone()),
            );
        } else if r.status == 200
            && !(r.status == ctrl_status && (r.body.len() as i64 - ctrl_len as i64).abs() < 30)
        {
            let sev = if SENSITIVE_MARKERS.iter().any(|m| p.contains(m)) {
                Severity::Medium
            } else {
                Severity::Low
            };
            out.push(
                Finding::new(
                    NAME,
                    sev,
                    format!("Reachable path: {p}"),
                    format!("HTTP 200 ({} bytes)", r.body.len()),
                )
                .with_evidence(p.clone()),
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_wordlist_normalizes_leading_slash() {
        let dir =
            std::env::temp_dir().join(format!("pentest-dast-wordlist-test-{}", std::process::id()));
        std::fs::write(&dir, "foo\n/bar\n\nbaz/qux\n").unwrap();
        let paths = load_wordlist(dir.to_str().unwrap());
        assert_eq!(paths, vec!["/foo", "/bar", "/baz/qux"]);
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn load_wordlist_returns_empty_for_missing_file() {
        assert_eq!(
            load_wordlist("/nonexistent/path/9182"),
            Vec::<String>::new()
        );
    }
}

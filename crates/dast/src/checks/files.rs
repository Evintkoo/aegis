use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, HttpRequest, Severity};

pub const NAME: &str = "files";

const SENSITIVE: &[(&str, Severity, &str, &str)] = &[
    (
        "/.git/HEAD",
        Severity::High,
        "exposed .git repository",
        "ref:",
    ),
    (
        "/.git/config",
        Severity::High,
        "exposed git config",
        "[core]",
    ),
    (
        "/.env",
        Severity::Critical,
        "exposed environment file (secrets)",
        "=",
    ),
    (
        "/.env.local",
        Severity::Critical,
        "exposed local env file",
        "=",
    ),
    ("/config.json", Severity::Medium, "exposed config", "{"),
    (
        "/wp-config.php.bak",
        Severity::Critical,
        "backup of WP config",
        "DB_PASSWORD",
    ),
    (
        "/backup.sql",
        Severity::Critical,
        "exposed SQL dump",
        "INSERT INTO",
    ),
    (
        "/.DS_Store",
        Severity::Low,
        "macOS directory metadata leak",
        "Bud1",
    ),
    (
        "/phpinfo.php",
        Severity::High,
        "phpinfo() exposed",
        "PHP Version",
    ),
    (
        "/server-status",
        Severity::Medium,
        "Apache server-status exposed",
        "Server Version",
    ),
    (
        "/actuator/env",
        Severity::High,
        "Spring Actuator env exposed",
        "propertySources",
    ),
    (
        "/.well-known/security.txt",
        Severity::Info,
        "security.txt present (good practice)",
        "Contact",
    ),
];

pub fn run<'a>(client: &'a HttpClient, opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(run_impl(client, opts))
}

async fn run_impl(client: &HttpClient, _opts: &Opts) -> Vec<Finding> {
    let mut out = Vec::new();
    let root = client.base_url_root();

    for (path, sev, why, marker) in SENSITIVE {
        if let Ok(r) = client
            .request(HttpRequest::get().url(format!("{root}{path}")))
            .await
        {
            if r.status == 200 && r.body.to_lowercase().contains(&marker.to_lowercase()) {
                out.push(
                    Finding::new(NAME, *sev, format!("Exposed {path}"), *why)
                        .with_evidence(r.body.chars().take(120).collect::<String>()),
                );
            }
        }
    }

    if let Ok(r) = client
        .request(HttpRequest::get().url(format!("{root}/")))
        .await
    {
        if r.body.contains("Index of /") || r.body.contains("<title>Directory listing") {
            out.push(
                Finding::new(
                    NAME,
                    Severity::Medium,
                    "Directory listing enabled",
                    "server returns an auto-index page",
                )
                .with_evidence("Index of /".to_string()),
            );
        }
    }

    out
}

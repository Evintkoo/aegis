use clap::Parser;
use pentest_core::cve::CveWriter;
use pentest_core::{HttpClient, HttpClientConfig, Report};
use pentest_dast::{verify, Opts};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pentest", about = "Authorized web pentest toolkit")]
struct Cli {
    /// Target base URL (may include ?param=val)
    #[arg(short = 'u', long = "url")]
    url: Option<String>,

    /// Header "Name: value" (repeatable)
    #[arg(short = 'H', long = "header")]
    header: Vec<String>,

    /// Seconds between requests
    #[arg(long, default_value_t = 0.4)]
    delay: f64,

    /// Comma list of checks to run
    #[arg(long)]
    only: Option<String>,

    /// Comma list of checks to skip
    #[arg(long)]
    skip: Option<String>,

    /// Print available checks and exit
    #[arg(long)]
    list_checks: bool,

    /// Extra paths for content_discovery (newline-delimited)
    #[arg(long)]
    wordlist: Option<String>,

    /// Skip the verification/proof pass
    #[arg(long)]
    no_exploit: bool,

    /// Write findings as a standalone HTML report
    #[arg(long)]
    html_out: Option<String>,

    /// Write findings as JSON to this file
    #[arg(long)]
    json_out: Option<String>,

    /// Disable TLS verification (self-signed dev hosts only!)
    #[arg(long)]
    insecure: bool,

    /// Actually send requests (else dry-run)
    #[arg(long)]
    confirm: bool,

    /// Directory to write CVE-schema finding records under
    #[arg(long, default_value = "cve")]
    cve_dir: String,

    /// Year to file CVE-schema records under (this plan has no datetime
    /// dependency to compute "now" from; override for cross-year runs)
    #[arg(long, default_value_t = 2026)]
    year: u32,
}

fn parse_headers(items: &[String]) -> HashMap<String, String> {
    let mut hdrs = HashMap::new();
    hdrs.insert("User-Agent".to_string(), "pentest-toolkit/1.0 (authorized)".to_string());
    for h in items {
        if let Some((k, v)) = h.split_once(':') {
            hdrs.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    hdrs
}

fn main() {
    let cli = Cli::parse();

    if cli.list_checks {
        println!("Available checks:");
        for c in pentest_dast::ALL {
            println!("  {}", c.name);
        }
        return;
    }

    let Some(url) = cli.url.clone() else {
        eprintln!("error: -u/--url is required (or pass --list-checks)");
        std::process::exit(2);
    };

    let mods: Vec<&pentest_dast::CheckEntry> = pentest_dast::ALL
        .iter()
        .filter(|c| {
            let in_only = cli.only.as_ref().is_none_or(|o| o.split(',').any(|n| n.trim() == c.name));
            let in_skip = cli.skip.as_ref().is_some_and(|s| s.split(',').any(|n| n.trim() == c.name));
            in_only && !in_skip
        })
        .collect();

    if !cli.confirm {
        println!("DRY RUN — no requests will be sent. Add --confirm to execute.\n");
        println!("  Target : GET {url}");
        println!("  Checks : {}", mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
        println!("  Delay  : {}s", cli.delay);
        println!("\nRun only against systems you own or are authorized to test.");
        return;
    }

    if cli.insecure {
        println!("WARNING: TLS verification DISABLED — only acceptable against your own self-signed dev host.\n");
    }

    let headers = parse_headers(&cli.header);
    let config = HttpClientConfig {
        headers: headers.clone(),
        delay: Duration::from_secs_f64(cli.delay),
        verify_tls: !cli.insecure,
        ..HttpClientConfig::default()
    };
    let client = HttpClient::new(url.clone(), config);
    let opts = Opts { wordlist: cli.wordlist.clone(), ..Opts::default() };

    let rt = tokio::runtime::Runtime::new().expect("failed to start async runtime");
    let mut report = Report::new();

    println!("[*] Site checks: {}", mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
    for m in &mods {
        let findings = rt.block_on((m.run)(&client, &opts));
        report.add(findings);
    }

    if !cli.no_exploit {
        println!("[*] Verifying findings (confidence, PoC)...");
    }
    for f in &mut report.findings {
        if f.remediation.is_empty() {
            f.remediation = verify::remediation_for(&f.check).to_string();
        }
        if !cli.no_exploit {
            if f.poc.is_empty() {
                f.poc = verify::poc_curl(f, &headers);
            }
            f.confidence = Some(verify::grade(f));
        }
    }

    report.print_console();

    if let Some(path) = &cli.json_out {
        std::fs::write(path, report.to_json()).expect("failed to write JSON report");
        println!("\n[+] JSON report written to {path}");
    }

    if let Some(path) = &cli.html_out {
        let meta = vec![
            ("Target".to_string(), format!("GET {url}")),
            ("Checks run".to_string(), mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", ")),
            ("Findings".to_string(), report.findings.len().to_string()),
        ];
        std::fs::write(path, report.to_html(&meta)).expect("failed to write HTML report");
        println!("[+] HTML report written to {path}");
    }

    if let Ok(writer) = CveWriter::new(&cli.cve_dir, cli.year) {
        if let Err(e) = report.write_cve_records(&writer) {
            eprintln!("warning: failed to write CVE records: {e}");
        }
    }

    let severe = report
        .findings
        .iter()
        .any(|f| matches!(f.severity, pentest_core::Severity::Critical | pentest_core::Severity::High));
    std::process::exit(if severe { 1 } else { 0 });
}

use clap::Parser;
use pentest_core::cve::CveWriter;
use pentest_core::{Finding, HttpClient, HttpClientConfig, Report, Severity};
use pentest_dast::{discover, verify, DiscoveryOpts, DiscoverySource, MineMode, Opts};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pentest", about = "Authorized web pentest toolkit")]
struct Cli {
    /// Target base URL (may include ?param=val)
    #[arg(short = 'u', long = "url")]
    url: Option<String>,

    /// Parameter to fuzz for SQLi/XSS/open-redirect (auto-discovered via
    /// crawling when omitted)
    #[arg(short = 'p', long = "param")]
    param: Option<String>,

    /// HTTP method to use for parameter checks when -p is given
    #[arg(long, default_value = "GET")]
    method: String,

    /// Header "Name: value" (repeatable)
    #[arg(short = 'H', long = "header")]
    header: Vec<String>,

    /// Seconds between requests
    #[arg(long, default_value_t = 0.4)]
    delay: f64,

    /// Seconds for time-based blind-injection payloads
    #[arg(long, default_value_t = 5)]
    sleep: u64,

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

    /// Max pages to crawl for param discovery (used when -p is omitted)
    #[arg(long, default_value_t = 10)]
    crawl_pages: usize,

    /// Max discovered params to fuzz (used when -p is omitted)
    #[arg(long, default_value_t = 25)]
    max_targets: usize,

    /// Don't auto-discover params when -p is omitted
    #[arg(long)]
    no_crawl: bool,

    /// Aggressive hidden-param brute-forcing (more endpoints)
    #[arg(long)]
    mine_params: bool,

    /// Disable hidden-param brute-forcing
    #[arg(long)]
    no_mine: bool,

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
    let site_mods: Vec<&pentest_dast::CheckEntry> =
        mods.iter().filter(|c| pentest_dast::SITE.iter().any(|s| s.name == c.name)).copied().collect();
    let param_mods: Vec<&pentest_dast::CheckEntry> =
        mods.iter().filter(|c| pentest_dast::PARAM.iter().any(|p| p.name == c.name)).copied().collect();

    if !cli.confirm {
        println!("DRY RUN — no requests will be sent. Add --confirm to execute.\n");
        println!("  Target : {} {url}", cli.method);
        let disc = if cli.no_crawl { "disabled (--no-crawl)" } else { "auto-discover via crawl" };
        println!("  Param  : {}", cli.param.as_deref().map(str::to_string).unwrap_or_else(|| format!("(none — {disc})")));
        println!("  Checks : {}", mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
        println!("  Delay  : {}s   Sleep: {}s", cli.delay, cli.sleep);
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
    let base_opts = Opts { wordlist: cli.wordlist.clone(), sleep: cli.sleep, ..Opts::default() };

    let rt = tokio::runtime::Runtime::new().expect("failed to start async runtime");
    let mut report = Report::new();

    println!("[*] Site checks: {}", site_mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
    let before = report.findings.len();
    for m in &site_mods {
        let findings = rt.block_on((m.run)(&client, &base_opts));
        report.add(findings);
    }
    for f in report.findings.iter_mut().skip(before) {
        if f.url.is_empty() {
            f.url = url.clone();
        }
    }

    if !param_mods.is_empty() {
        if let Some(param) = cli.param.clone() {
            println!("[*] Param checks on '{param}': {}", param_mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
            let base_value = reqwest::Url::parse(&url)
                .ok()
                .and_then(|u| u.query_pairs().find(|(k, _)| k == param.as_str()).map(|(_, v)| v.into_owned()))
                .unwrap_or_else(|| "1".to_string());
            let opts = Opts { param: Some(param.clone()), method: cli.method.clone(), base_value, ..base_opts.clone() };
            let before = report.findings.len();
            for m in &param_mods {
                let findings = rt.block_on((m.run)(&client, &opts));
                report.add(findings);
            }
            for f in report.findings.iter_mut().skip(before) {
                f.url = url.clone();
                f.param = param.clone();
                f.method = cli.method.clone();
            }
        } else if !cli.no_crawl {
            let mine = if cli.no_mine {
                MineMode::Off
            } else if cli.mine_params {
                MineMode::Aggressive
            } else {
                MineMode::Auto
            };
            let discovery_opts = DiscoveryOpts { crawl_pages: cli.crawl_pages, max_targets: cli.max_targets, mine };
            let targets = rt.block_on(discover(&client, &url, &discovery_opts));
            for (i, t) in targets.iter().enumerate() {
                let ep = t.url.split('?').next().unwrap_or(&t.url);
                if t.source == DiscoverySource::Mined {
                    report.add(vec![Finding::new(
                        "discovery",
                        Severity::Info,
                        "Hidden parameter discovered",
                        format!("'{}' is honored by {ep} but not exposed in the HTML — found via parameter mining", t.param),
                    )
                    .with_evidence(format!("{ep} · {}", t.param))]);
                }
                println!("[*] ({}/{}) fuzzing {} {ep} · param '{}' (via {})", i + 1, targets.len(), t.method, t.param, t.source.as_str());
                let tclient = HttpClient::new(
                    t.url.clone(),
                    HttpClientConfig { headers: headers.clone(), delay: Duration::from_secs_f64(cli.delay), verify_tls: !cli.insecure, ..HttpClientConfig::default() },
                );
                let topts = Opts { param: Some(t.param.clone()), method: t.method.clone(), base_value: t.value.clone(), ..base_opts.clone() };
                let before = report.findings.len();
                for m in &param_mods {
                    let findings = rt.block_on((m.run)(&tclient, &topts));
                    report.add(findings);
                }
                for f in report.findings.iter_mut().skip(before) {
                    f.url = t.url.clone();
                    f.param = t.param.clone();
                    f.method = t.method.clone();
                    f.detail = format!("[{} {ep} · {}] {}", t.method, t.param, f.detail);
                }
            }
        } else {
            println!("[*] Param checks skipped (no -p and --no-crawl set)");
        }
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
        match std::fs::write(path, report.to_json()) {
            Ok(()) => println!("\n[+] JSON report written to {path}"),
            Err(e) => eprintln!("warning: failed to write JSON report: {e}"),
        }
    }

    if let Some(path) = &cli.html_out {
        let meta = vec![
            ("Target".to_string(), format!("GET {url}")),
            ("Checks run".to_string(), mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", ")),
            ("Findings".to_string(), report.findings.len().to_string()),
        ];
        match std::fs::write(path, report.to_html(&meta)) {
            Ok(()) => println!("[+] HTML report written to {path}"),
            Err(e) => eprintln!("warning: failed to write HTML report: {e}"),
        }
    }

    match CveWriter::new(&cli.cve_dir, cli.year) {
        Ok(writer) => {
            if let Err(e) = report.write_cve_records(&writer) {
                eprintln!("warning: failed to write CVE records: {e}");
            }
        }
        Err(e) => eprintln!("warning: failed to initialize CVE writer: {e}"),
    }

    let severe = report
        .findings
        .iter()
        .any(|f| matches!(f.severity, pentest_core::Severity::Critical | pentest_core::Severity::High));
    std::process::exit(if severe { 1 } else { 0 });
}

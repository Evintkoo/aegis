use clap::Parser;
use pentest_core::cve::CveWriter;
use pentest_core::{Finding, HttpClient, HttpClientConfig, Report, Severity};
use pentest_cve_lookup::{enrich_findings, LookupOpts, CVE_MATCH_CHECK};
use pentest_dast::{discover, verify, DiscoveryOpts, DiscoverySource, MineMode, Opts};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pentest", version, about = "Authorized web pentest toolkit")]
struct Cli {
    /// Target base URL (may include ?param=val)
    #[arg(short = 'u', long = "url")]
    url: Option<String>,

    /// Source directory to run static analysis (SAST) against. Reads
    /// local files only -- never gated behind --confirm, unlike DAST's
    /// network checks. May be combined with -u or used standalone.
    #[arg(long = "src")]
    src: Option<String>,

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

    /// Print the final findings report as JSON on stdout and move all
    /// human progress output to stderr — machine-readable mode for CI
    /// and agent use
    #[arg(long)]
    json: bool,

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

    /// A URL you monitor, for out-of-band SSRF confirmation
    #[arg(long)]
    ssrf_callback: Option<String>,

    /// Base URL of a running pentest-collaborator listener, for blind OOB checks
    #[arg(long)]
    collaborator: Option<String>,

    /// Also run installed sqlmap/nikto/nuclei
    #[arg(long)]
    external: bool,

    /// Login endpoint (enables auth_bruteforce)
    #[arg(long)]
    login_url: Option<String>,

    /// A username you own that exists (for enumeration test)
    #[arg(long)]
    auth_username: Option<String>,

    /// Login username field name
    #[arg(long, default_value = "username")]
    user_field: String,

    /// Login password field name
    #[arg(long, default_value = "password")]
    pass_field: String,

    /// Send login as JSON instead of form
    #[arg(long)]
    auth_json: bool,

    /// Bad-login attempts (max 5)
    #[arg(long, default_value_t = 4)]
    auth_attempts: u64,

    /// Real CVE matching via OSV.dev (on by default; accepted for
    /// symmetry with --no-osv, matching Python's --foo/--no-foo
    /// argparse convention -- it's a no-op since true is already default)
    #[arg(long)]
    osv: bool,

    /// Disable OSV.dev CVE matching
    #[arg(long)]
    no_osv: bool,

    /// Enable NVD enrichment for infra/banner matches (default: off)
    #[arg(long)]
    nvd_api_key: Option<String>,
}

/// Suppresses "... check skipped — no --param" style info noise, matching
/// `run_all.py`'s `_is_skip_notice`. `jwt` is currently the only check
/// that emits this shape of finding.
fn is_skip_notice(f: &Finding) -> bool {
    f.severity == Severity::Info && f.title.to_lowercase().contains("skip")
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

    let json_mode = cli.json;
    macro_rules! note {
        ($($arg:tt)*) => {
            if json_mode { eprintln!($($arg)*); } else { println!($($arg)*); }
        };
    }

    if cli.list_checks {
        if cli.json {
            let checks: Vec<serde_json::Value> = pentest_dast::ALL
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "kind": if pentest_dast::PARAM.iter().any(|p| p.name == c.name) { "param" } else { "site" },
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&checks).unwrap_or_else(|_| "[]".to_string()));
        } else {
            println!("Available checks:");
            for c in pentest_dast::ALL {
                println!("  {}", c.name);
            }
        }
        return;
    }

    if cli.url.is_none() && cli.src.is_none() {
        eprintln!("error: -u/--url or --src is required (or pass --list-checks)");
        std::process::exit(2);
    }

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

    let headers = parse_headers(&cli.header);
    let rt = tokio::runtime::Runtime::new().expect("failed to start async runtime");
    let mut report = Report::new();

    // SAST: reads local files only, never a network action against the
    // target -- deliberately NOT gated behind --confirm, unlike every DAST
    // check below (that gate exists solely to stop unconfirmed requests
    // reaching a pentest target; a local source-tree scan sends none).
    // Runs whenever --src is given, standalone or alongside -u.
    if let Some(src) = &cli.src {
        note!("[*] SAST scan: {src}");
        // Exclude this run's CVE output directory (if it already exists,
        // e.g. from a prior run) from the scan by canonicalized path --
        // never by name -- so a `cve/` directory under `--src` doesn't
        // create a self-scan feedback loop: findings' evidence text (which
        // can contain a raw secret) gets written there as JSON, which the
        // secrets rule would otherwise re-detect on the next run, writing
        // more records, compounding without bound. `canonicalize` fails
        // when the directory doesn't exist yet (the common case for a
        // fresh run, since it's created lazily on first write below) --
        // that's not an error, it just means there's nothing to exclude.
        let exclude: Vec<std::path::PathBuf> = std::fs::canonicalize(&cli.cve_dir).into_iter().collect();
        let sast_findings = pentest_sast::scan(std::path::Path::new(src), &exclude);
        note!("[*] SAST: {} finding(s)", sast_findings.len());
        report.add(sast_findings);
    }

    let dast_ran = cli.url.is_some() && cli.confirm;

    if let Some(url) = cli.url.clone() {
        if !cli.confirm {
            note!("DRY RUN — no requests will be sent. Add --confirm to execute.\n");
            note!("  Target : {} {url}", cli.method);
            let disc = if cli.no_crawl { "disabled (--no-crawl)" } else { "auto-discover via crawl" };
            note!("  Param  : {}", cli.param.as_deref().map(str::to_string).unwrap_or_else(|| format!("(none — {disc})")));
            note!("  Checks : {}", mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
            note!("  Delay  : {}s   Sleep: {}s", cli.delay, cli.sleep);
            note!("\nRun only against systems you own or are authorized to test.");
            if cli.src.is_none() && !json_mode {
                // Pure DAST dry-run (no --src): preserve the original
                // behavior of stopping here, before any report/CVE
                // pipeline runs. In --json mode the run instead falls
                // through with zero findings so stdout always carries a
                // parseable findings array for the calling agent/CI.
                return;
            }
        } else {
            if cli.insecure {
                note!("WARNING: TLS verification DISABLED — only acceptable against your own self-signed dev host.\n");
            }

            let config = HttpClientConfig {
                headers: headers.clone(),
                delay: Duration::from_secs_f64(cli.delay),
                verify_tls: !cli.insecure,
                ..HttpClientConfig::default()
            };
            let client = HttpClient::new(url.clone(), config);
            // Carries every opt-in/logic-check field alongside param/method so
            // site checks see the same shared opts Python's run_all.py builds
            // once and reuses everywhere -- ssrf/redirect/blind_oob (site checks
            // that opportunistically use opts.param when present) previously saw
            // neither -p nor --method during the site-checks phase, a gap that
            // stayed invisible until these checks existed.
            let base_opts = Opts {
                param: cli.param.clone(),
                method: cli.method.clone(),
                wordlist: cli.wordlist.clone(),
                sleep: cli.sleep,
                ssrf_callback: cli.ssrf_callback.clone(),
                collaborator: cli.collaborator.clone(),
                external: cli.external,
                login_url: cli.login_url.clone(),
                auth_username: cli.auth_username.clone(),
                user_field: cli.user_field.clone(),
                pass_field: cli.pass_field.clone(),
                auth_json: cli.auth_json,
                auth_attempts: cli.auth_attempts,
                ..Opts::default()
            };

            note!("[*] Site checks: {}", site_mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
            let before = report.findings.len();
            for m in &site_mods {
                let findings = rt.block_on((m.run)(&client, &base_opts));
                report.add(findings.into_iter().filter(|f| !is_skip_notice(f)).collect());
            }
            for f in report.findings.iter_mut().skip(before) {
                if f.url.is_empty() {
                    f.url = url.clone();
                }
            }

            if !param_mods.is_empty() {
                if let Some(param) = cli.param.clone() {
                    note!("[*] Param checks on '{param}': {}", param_mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "));
                    let base_value = reqwest::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.query_pairs().find(|(k, _)| k == param.as_str()).map(|(_, v)| v.into_owned()))
                        .unwrap_or_else(|| "1".to_string());
                    let opts = Opts { param: Some(param.clone()), method: cli.method.clone(), base_value, ..base_opts.clone() };
                    let before = report.findings.len();
                    for m in &param_mods {
                        let findings = rt.block_on((m.run)(&client, &opts));
                        report.add(findings.into_iter().filter(|f| !is_skip_notice(f)).collect());
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
                        note!("[*] ({}/{}) fuzzing {} {ep} · param '{}' (via {})", i + 1, targets.len(), t.method, t.param, t.source.as_str());
                        let tclient = HttpClient::new(
                            t.url.clone(),
                            HttpClientConfig { headers: headers.clone(), delay: Duration::from_secs_f64(cli.delay), verify_tls: !cli.insecure, ..HttpClientConfig::default() },
                        );
                        let topts = Opts { param: Some(t.param.clone()), method: t.method.clone(), base_value: t.value.clone(), ..base_opts.clone() };
                        let before = report.findings.len();
                        for m in &param_mods {
                            let findings = rt.block_on((m.run)(&tclient, &topts));
                            report.add(findings.into_iter().filter(|f| !is_skip_notice(f)).collect());
                        }
                        for f in report.findings.iter_mut().skip(before) {
                            f.url = t.url.clone();
                            f.param = t.param.clone();
                            f.method = t.method.clone();
                            f.detail = format!("[{} {ep} · {}] {}", t.method, t.param, f.detail);
                        }
                    }
                } else {
                    note!("[*] Param checks skipped (no -p and --no-crawl set)");
                }
            }
        }
    }

    let cve_writer = match CveWriter::new(&cli.cve_dir, cli.year) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("warning: failed to initialize CVE writer: {e}");
            None
        }
    };

    // Real CVE/advisory matching (opt-in per-source: --no-osv turns off
    // OSV.dev, --nvd-api-key turns on NVD; both independently controlled,
    // matching the design spec's flag table). `enrich_findings` scans for
    // a `component/version`-shaped banner (currently only `recon`'s
    // "<Header> header exposed" findings carry one), looks each up, and
    // writes any match's real-or-native record to disk. OSV.dev has no
    // ecosystem for arbitrary infra software, so this is expected to
    // reliably return no OSV hits for banner-derived fingerprints -- real
    // detection for THIS signal type comes from NVD's keywordSearch, per
    // the spec's own rationale for why NVD exists alongside OSV. OSV is
    // still queried regardless (harmless: an unmatched ecosystem is
    // treated the same as "no match"), so a future fingerprint source
    // that DOES know a real OSV ecosystem benefits with no changes here.
    let osv_enabled = !cli.no_osv;
    if let Some(writer) = &cve_writer {
        if osv_enabled || cli.nvd_api_key.is_some() {
            let lookup_opts = LookupOpts { osv_enabled, nvd_api_key: cli.nvd_api_key.clone(), ..LookupOpts::enabled() };
            let matched_findings = rt.block_on(enrich_findings(&report.findings, writer, &lookup_opts, cli.year));
            report.add(matched_findings);
        }
    }

    if !cli.no_exploit {
        note!("[*] Verifying findings (confidence, PoC)...");
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

    if json_mode {
        println!("{}", report.to_json());
    } else {
        report.print_console();
    }

    if let Some(path) = &cli.json_out {
        match std::fs::write(path, report.to_json()) {
            Ok(()) => note!("\n[+] JSON report written to {path}"),
            Err(e) => eprintln!("warning: failed to write JSON report: {e}"),
        }
    }

    if let Some(path) = &cli.html_out {
        let mut meta = vec![(
            "Target".to_string(),
            cli.url.as_deref().map(|u| format!("{} {u}", cli.method)).unwrap_or_else(|| "(none — SAST-only run)".to_string()),
        )];
        if let Some(src) = &cli.src {
            meta.push(("Source dir".to_string(), src.clone()));
        }
        if dast_ran {
            meta.push(("Checks run".to_string(), mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", ")));
        }
        meta.push(("Findings".to_string(), report.findings.len().to_string()));
        match std::fs::write(path, report.to_html(&meta)) {
            Ok(()) => note!("[+] HTML report written to {path}"),
            Err(e) => eprintln!("warning: failed to write HTML report: {e}"),
        }
    }

    // `cve-match` findings already got their own real-CVE/native-advisory
    // record written above via write_real_cve/write_native_advisory -- a
    // self-discovered local PENTEST-LOCAL-* record here would be a
    // fabricated ID competing with the real one, which the spec's
    // non-goals explicitly forbid. Everything else still gets its usual
    // local record.
    if let Some(writer) = &cve_writer {
        let mut local_only = Report::new();
        local_only.add(report.findings.iter().filter(|f| f.check != CVE_MATCH_CHECK).cloned().collect());
        if let Err(e) = local_only.write_cve_records(writer) {
            eprintln!("warning: failed to write CVE records: {e}");
        }
    }

    let severe = report
        .findings
        .iter()
        .any(|f| matches!(f.severity, pentest_core::Severity::Critical | pentest_core::Severity::High));
    std::process::exit(if severe { 1 } else { 0 });
}

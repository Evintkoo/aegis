use clap::Parser;
use futures::FutureExt;
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

    /// Year to file CVE-schema records under. Defaults to the current
    /// calendar year (UTC) derived from the system clock; override for
    /// reproducible cross-year runs.
    #[arg(long)]
    year: Option<u32>,

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

    /// Opt-in: concurrent duplicate-request burst to detect missing
    /// locking (race_condition). Off by default — the burst multiplies
    /// request volume against the target.
    #[arg(long)]
    race: bool,

    /// Opt-in: bounded request-smuggling framing probes (http targets
    /// only). Off by default — conflicting-header probes can desync a
    /// vulnerable front-end's connection reuse.
    #[arg(long)]
    smuggling: bool,

    /// Opt-in: out-of-domain values (negative/zero/overflow) on the
    /// target param (business_logic). Off by default — on POST endpoints
    /// these values can be state-changing; staging targets only.
    #[arg(long)]
    logic: bool,

    /// Opt-in: enumerate accepted TLS protocol versions on https targets
    /// via direct ClientHello probes (tls_enum).
    #[arg(long)]
    tls_enum: bool,

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
/// that emits this shape of finding. Panic records (`run_check`'s
/// "panicked — skipped" findings) carry "skip" in their title too but must
/// stay visible, so they're exempt here.
fn is_skip_notice(f: &Finding) -> bool {
    f.severity == Severity::Info
        && f.title.to_lowercase().contains("skip")
        && !f.title.to_lowercase().contains("panic")
}

/// Awaits one check future, converting a panic inside it into an Info
/// finding (plus a stderr warning) instead of letting it abort the whole
/// run — an aborted run loses every other check's findings.
async fn run_check(
    name: &str,
    fut: impl std::future::Future<Output = Vec<Finding>>,
) -> Vec<Finding> {
    match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
        Ok(findings) => findings,
        Err(panic) => {
            let payload = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic payload".to_string());
            eprintln!("warning: check '{name}' panicked — skipped: {payload}");
            vec![Finding::new(
                name,
                Severity::Info,
                format!("check '{name}' panicked — skipped"),
                "the check aborted mid-run; the rest of the scan continued",
            )
            .with_evidence(payload)]
        }
    }
}

fn parse_headers(items: &[String]) -> HashMap<String, String> {
    let mut hdrs = HashMap::new();
    hdrs.insert(
        "User-Agent".to_string(),
        "pentest-toolkit/1.0 (authorized)".to_string(),
    );
    for h in items {
        if let Some((k, v)) = h.split_once(':') {
            hdrs.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    hdrs
}

/// Converts days since the Unix epoch to a proleptic-Gregorian year
/// (Howard Hinnant's `civil_from_days` algorithm, exact across leap
/// years — no drift from averaging year lengths).
fn year_from_days(days: i64) -> i64 {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    if mp < 10 {
        y
    } else {
        y + 1
    }
}

/// Current UTC calendar year; falls back to 2026 only if the system
/// clock is set before the Unix epoch.
fn current_year() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| year_from_days(d.as_secs() as i64 / 86_400) as u32)
        .unwrap_or(2026)
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
                        "refs": pentest_core::standards::refs_for(c.name),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&checks).unwrap_or_else(|_| "[]".to_string())
            );
        } else {
            println!("Available checks:");
            for c in pentest_dast::ALL {
                let refs = pentest_core::standards::refs_for(c.name);
                if refs.is_empty() {
                    println!("  {}", c.name);
                } else {
                    println!("  {} — {}", c.name, refs.join(" · "));
                }
            }
        }
        return;
    }

    if cli.url.is_none() && cli.src.is_none() {
        eprintln!("error: -u/--url or --src is required (or pass --list-checks)");
        std::process::exit(2);
    }

    let year = cli.year.unwrap_or_else(current_year);

    let mods: Vec<&pentest_dast::CheckEntry> = pentest_dast::ALL
        .iter()
        .filter(|c| {
            let in_only = cli
                .only
                .as_ref()
                .is_none_or(|o| o.split(',').any(|n| n.trim() == c.name));
            let in_skip = cli
                .skip
                .as_ref()
                .is_some_and(|s| s.split(',').any(|n| n.trim() == c.name));
            in_only && !in_skip
        })
        .collect();
    let site_mods: Vec<&pentest_dast::CheckEntry> = mods
        .iter()
        .filter(|c| pentest_dast::SITE.iter().any(|s| s.name == c.name))
        .copied()
        .collect();
    let param_mods: Vec<&pentest_dast::CheckEntry> = mods
        .iter()
        .filter(|c| pentest_dast::PARAM.iter().any(|p| p.name == c.name))
        .copied()
        .collect();

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
        let exclude: Vec<std::path::PathBuf> =
            std::fs::canonicalize(&cli.cve_dir).into_iter().collect();
        let sast_findings = pentest_sast::scan(std::path::Path::new(src), &exclude);
        note!("[*] SAST: {} finding(s)", sast_findings.len());
        report.add(sast_findings);
    }

    let dast_ran = cli.url.is_some() && cli.confirm;

    if let Some(url) = cli.url.clone() {
        if !cli.confirm {
            note!("DRY RUN — no requests will be sent. Add --confirm to execute.\n");
            note!("  Target : {} {url}", cli.method);
            let disc = if cli.no_crawl {
                "disabled (--no-crawl)"
            } else {
                "auto-discover via crawl"
            };
            note!(
                "  Param  : {}",
                cli.param
                    .as_deref()
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("(none — {disc})"))
            );
            note!(
                "  Checks : {}",
                mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", ")
            );
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
                smuggling: cli.smuggling,
                race: cli.race,
                logic: cli.logic,
                tls_enum: cli.tls_enum,
                ..Opts::default()
            };

            note!(
                "[*] Site checks: {}",
                site_mods
                    .iter()
                    .map(|c| c.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let before = report.findings.len();
            for m in &site_mods {
                let findings = rt
                    .block_on(run_check(m.name, (m.run)(&client, &base_opts)))
                    .into_iter()
                    .filter(|f| !is_skip_notice(f))
                    .collect();
                report.add(findings);
            }
            for f in report.findings.iter_mut().skip(before) {
                if f.url.is_empty() {
                    f.url = url.clone();
                }
            }

            if !param_mods.is_empty() {
                if let Some(param) = cli.param.clone() {
                    note!(
                        "[*] Param checks on '{param}': {}",
                        param_mods
                            .iter()
                            .map(|c| c.name)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    let base_value = reqwest::Url::parse(&url)
                        .ok()
                        .and_then(|u| {
                            u.query_pairs()
                                .find(|(k, _)| k == param.as_str())
                                .map(|(_, v)| v.into_owned())
                        })
                        .unwrap_or_else(|| "1".to_string());
                    let opts = Opts {
                        param: Some(param.clone()),
                        method: cli.method.clone(),
                        base_value,
                        ..base_opts.clone()
                    };
                    let before = report.findings.len();
                    for m in &param_mods {
                        let findings = rt
                            .block_on(run_check(m.name, (m.run)(&client, &opts)))
                            .into_iter()
                            .filter(|f| !is_skip_notice(f))
                            .collect();
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
                    let discovery_opts = DiscoveryOpts {
                        crawl_pages: cli.crawl_pages,
                        max_targets: cli.max_targets,
                        mine,
                    };
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
                        note!(
                            "[*] ({}/{}) fuzzing {} {ep} · param '{}' (via {})",
                            i + 1,
                            targets.len(),
                            t.method,
                            t.param,
                            t.source.as_str()
                        );
                        let tclient = HttpClient::new(
                            t.url.clone(),
                            HttpClientConfig {
                                headers: headers.clone(),
                                delay: Duration::from_secs_f64(cli.delay),
                                verify_tls: !cli.insecure,
                                ..HttpClientConfig::default()
                            },
                        );
                        let topts = Opts {
                            param: Some(t.param.clone()),
                            method: t.method.clone(),
                            base_value: t.value.clone(),
                            ..base_opts.clone()
                        };
                        let before = report.findings.len();
                        for m in &param_mods {
                            let findings = rt
                                .block_on(run_check(m.name, (m.run)(&tclient, &topts)))
                                .into_iter()
                                .filter(|f| !is_skip_notice(f))
                                .collect();
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
                    note!("[*] Param checks skipped (no -p and --no-crawl set)");
                }
            }
        }
    }

    let cve_writer = match CveWriter::new(&cli.cve_dir, year) {
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
            let lookup_opts = LookupOpts {
                osv_enabled,
                nvd_api_key: cli.nvd_api_key.clone(),
                ..LookupOpts::enabled()
            };
            let matched_findings = rt.block_on(enrich_findings(
                &report.findings,
                writer,
                &lookup_opts,
                year,
            ));
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
        if f.refs.is_empty() {
            f.refs = pentest_core::standards::refs_for(&f.check)
                .iter()
                .map(|s| s.to_string())
                .collect();
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
            cli.url
                .as_deref()
                .map(|u| format!("{} {u}", cli.method))
                .unwrap_or_else(|| "(none — SAST-only run)".to_string()),
        )];
        if let Some(src) = &cli.src {
            meta.push(("Source dir".to_string(), src.clone()));
        }
        if dast_ran {
            meta.push((
                "Checks run".to_string(),
                mods.iter().map(|c| c.name).collect::<Vec<_>>().join(", "),
            ));
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
        local_only.add(
            report
                .findings
                .iter()
                .filter(|f| f.check != CVE_MATCH_CHECK)
                .cloned()
                .collect(),
        );
        if let Err(e) = local_only.write_cve_records(writer) {
            eprintln!("warning: failed to write CVE records: {e}");
        }
    }

    let severe = report.findings.iter().any(|f| {
        matches!(
            f.severity,
            pentest_core::Severity::Critical | pentest_core::Severity::High
        )
    });
    std::process::exit(if severe { 1 } else { 0 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_from_days_matches_known_dates() {
        // 1970-01-01, 2024-02-29 (leap day), 2024-12-31, 2025-01-01,
        // 2026-09-18, 2100-03-01 (the day after non-leap century year
        // 2100's February ends).
        for (days, expected) in [
            (0i64, 1970),
            (19782, 2024),
            (20088, 2024),
            (20089, 2025),
            (20683, 2026),
            (47482, 2100),
        ] {
            assert_eq!(year_from_days(days), expected, "days={days}");
        }
    }

    #[test]
    fn current_year_is_a_plausible_calendar_year() {
        let y = current_year();
        assert!(
            (2026..=2200).contains(&y),
            "implausible system-clock year: {y}"
        );
    }

    #[test]
    fn is_skip_notice_exempts_panic_records() {
        let panic_record = Finding::new(
            "boom",
            Severity::Info,
            "check 'boom' panicked — skipped",
            "the check aborted mid-run",
        );
        assert!(!is_skip_notice(&panic_record));

        let skip_notice =
            Finding::new("jwt", Severity::Info, "jwt check skipped — no token", "n/a");
        assert!(is_skip_notice(&skip_notice));
    }

    #[tokio::test]
    async fn run_check_passes_a_healthy_finding_through() {
        let findings = run_check("ok", async {
            vec![Finding::new("ok", Severity::High, "t", "d")]
        })
        .await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "t");
    }

    #[tokio::test]
    async fn run_check_turns_a_panicking_check_into_an_info_finding() {
        async fn panicking_check() -> Vec<Finding> {
            panic!("kaboom at stage 2");
        }

        let findings = run_check("boom", panicking_check()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].check, "boom");
        assert!(
            findings[0].title.contains("panicked — skipped"),
            "got {}",
            findings[0].title
        );
        assert_eq!(findings[0].evidence, "kaboom at stage 2");
    }

    #[tokio::test]
    async fn run_check_reports_an_opaque_panic_payload() {
        async fn opaque_panic() -> Vec<Finding> {
            std::panic::panic_any(42u32);
        }

        let findings = run_check("opaque", opaque_panic()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "unknown panic payload");
    }
}

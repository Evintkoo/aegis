#!/usr/bin/env python3
"""
run_all.py — Authorized web pentest orchestrator.

Runs every check module in checks/ against a single target and prints a
combined, severity-sorted report. Detection-only, rate-limited, dry-run
by default.

  >>> ONLY run against a system you own or are explicitly authorized to test. <<<

Examples
--------
  # Auto-discovery: no -p needed — crawls links/forms to find params to fuzz:
  python3 run_all.py -u "https://staging.myapp.test/" --confirm

  # Target a specific parameter explicitly:
  python3 run_all.py -u "https://staging.myapp.test/item?id=1" -p id --confirm

  # POST param, with auth, JSON report to file:
  python3 run_all.py -u "https://staging.myapp.test/search" -p q --method POST \
      -H "Cookie: session=abc" --confirm --json-out report.json

  # Run only some checks:
  python3 run_all.py -u "..." -p id --only headers,sqli --confirm

  # Skip checks:
  python3 run_all.py -u "..." -p id --skip files,recon --confirm
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import HttpClient, Report, Finding   # noqa: E402
from discovery import discover                   # noqa: E402
import exploit                                    # noqa: E402
import checks                                    # noqa: E402

# Checks that need a specific parameter to fuzz. When -p is omitted we
# auto-discover parameters (crawl links + forms) and run these per target.
PARAM_CHECKS = {"sqli", "nosqli", "cmdi", "ssti", "traversal", "crlf", "xss",
                "ldap_injection", "xpath_injection", "idor"}


def _is_skip_notice(f):
    """Suppress '… check skipped — no --param' style info noise."""
    return f.severity == "info" and "skip" in (f.title or "").lower()


def parse_headers(items):
    hdrs = {"User-Agent": "pentest-toolkit/1.0 (authorized)"}
    for h in items:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return hdrs


def select_modules(only, skip):
    mods = list(checks.ALL)
    if only:
        want = {s.strip() for s in only.split(",")}
        mods = [m for m in mods if m.NAME in want]
    if skip:
        drop = {s.strip() for s in skip.split(",")}
        mods = [m for m in mods if m.NAME not in drop]
    return mods


def main():
    ap = argparse.ArgumentParser(description="Authorized web pentest — run all checks.")
    ap.add_argument("-u", "--url", required=True, help="Target base URL (may include ?param=val)")
    ap.add_argument("-p", "--param", help="Parameter to fuzz for SQLi/XSS/open-redirect")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("-H", "--header", action="append", default=[], help="Header 'Name: value' (repeatable)")
    ap.add_argument("--delay", type=float, default=0.4, help="Seconds between requests")
    ap.add_argument("--sleep", type=int, default=5, help="Seconds for time-based SQLi payload")
    ap.add_argument("--only", help="Comma list of checks to run (see --list-checks)")
    ap.add_argument("--skip", help="Comma list of checks to skip")
    ap.add_argument("--list-checks", action="store_true", help="Print available check names and exit")
    ap.add_argument("--ssrf-callback", help="A URL you monitor, for out-of-band SSRF confirmation")
    ap.add_argument("--collaborator", help="Base URL of a running collaborator.py for blind OOB checks")
    ap.add_argument("--external", action="store_true", help="Also run installed sqlmap/nikto/nuclei")
    ap.add_argument("--wordlist", help="Path to newline-delimited paths for content discovery")
    # auto-discovery (used when -p is not given)
    ap.add_argument("--crawl-pages", type=int, default=10, help="Max pages to crawl for param discovery")
    ap.add_argument("--max-targets", type=int, default=25, help="Max discovered params to fuzz")
    ap.add_argument("--no-crawl", action="store_true", help="Don't auto-discover params when -p is omitted")
    ap.add_argument("--mine-params", action="store_true", help="Aggressive hidden-param brute-forcing (more endpoints)")
    ap.add_argument("--no-mine", action="store_true", help="Disable hidden-param brute-forcing")
    ap.add_argument("--no-exploit", action="store_true",
                    help="Skip the verification/proof pass (no DB-version extraction, no PoC)")
    # auth_bruteforce (opt-in, bounded) — your own login only
    ap.add_argument("--login-url", help="Login endpoint (enables auth_bruteforce)")
    ap.add_argument("--auth-username", help="A username you own that exists (for enumeration test)")
    ap.add_argument("--user-field", default="username", help="Login username field name")
    ap.add_argument("--pass-field", default="password", help="Login password field name")
    ap.add_argument("--auth-json", action="store_true", help="Send login as JSON instead of form")
    ap.add_argument("--auth-attempts", type=int, default=4, help="Bad-login attempts (max 5)")
    # reporting
    ap.add_argument("--html-out", help="Write findings as a standalone HTML report")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification (self-signed dev only!)")
    ap.add_argument("--json-out", help="Write findings as JSON to this file")
    ap.add_argument("--confirm", action="store_true", help="Actually send requests (else dry-run)")
    args = ap.parse_args()

    if args.list_checks:
        print("Available checks:")
        for m in checks.ALL:
            print(f"  {m.NAME:18} — {(m.__doc__ or '').strip().splitlines()[0]}")
        return

    mods = select_modules(args.only, args.skip)
    base_value = "1"
    import urllib.parse
    q = urllib.parse.parse_qs(urllib.parse.urlparse(args.url).query)
    if args.param and args.param in q:
        base_value = q[args.param][0]

    if not args.confirm:
        print("DRY RUN — no requests will be sent. Add --confirm to execute.\n")
        print(f"  Target : {args.method} {args.url}")
        disc = "auto-discover via crawl" if not args.no_crawl else "disabled (--no-crawl)"
        print(f"  Param  : {args.param or f'(none — {disc})'}")
        print(f"  Checks : {', '.join(m.NAME for m in mods)}")
        print(f"  Delay  : {args.delay}s   Sleep: {args.sleep}s")
        print("\nRun only against systems you own or are authorized to test.")
        return

    if args.insecure:
        print("⚠️  TLS verification DISABLED — only acceptable against your own self-signed "
              "dev host. Never use against anything you don't fully control.\n")

    client = HttpClient(
        base_url=args.url,
        headers=parse_headers(args.header),
        delay=args.delay,
        verify_tls=not args.insecure,
    )
    opts = {
        "param": args.param,
        "method": args.method,
        "base_value": base_value,
        "sleep": args.sleep,
        "ssrf_callback": args.ssrf_callback,
        "collaborator": args.collaborator,
        "external": args.external,
        "wordlist": args.wordlist,
        "login_url": args.login_url,
        "auth_username": args.auth_username,
        "user_field": args.user_field,
        "pass_field": args.pass_field,
        "auth_json": args.auth_json,
        "auth_attempts": args.auth_attempts,
    }

    report = Report()
    site_mods = [m for m in mods if m.NAME not in PARAM_CHECKS]
    param_mods = [m for m in mods if m.NAME in PARAM_CHECKS]

    def add(findings):
        report.add([f for f in (findings or []) if not _is_skip_notice(f)])

    def run_mods(mod_list, cli, o, tag=None):
        for m in mod_list:
            try:
                add(m.run(cli, o))
            except Exception as e:
                print(f"    (check '{m.NAME}'{' @ ' + tag if tag else ''} errored: {e})")

    # 1) Site-level checks — run once against the base URL
    print(f"[*] Site checks: {', '.join(m.NAME for m in site_mods)}")
    before = len(report.findings)
    run_mods(site_mods, client, opts)
    for f in report.findings[before:]:
        f.url = f.url or args.url

    # 2) Parameter checks
    if param_mods:
        if args.param:
            print(f"[*] Param checks on '{args.param}': {', '.join(m.NAME for m in param_mods)}")
            before = len(report.findings)
            run_mods(param_mods, client, opts)
            for f in report.findings[before:]:
                f.url, f.param, f.method = args.url, args.param, args.method
        elif not args.no_crawl:
            mine = "off" if args.no_mine else ("aggressive" if args.mine_params else "auto")
            targets = discover(client, args.url, max_pages=args.crawl_pages,
                               max_targets=args.max_targets, mine=mine)
            hdrs = parse_headers(args.header)
            for i, t in enumerate(targets, 1):
                ep = t["url"].split("?")[0]
                if t.get("source") == "mined":
                    add([Finding("discovery", "info", "Hidden parameter discovered",
                                 f"'{t['param']}' is honored by {ep} but not exposed in the "
                                 f"HTML — found via parameter mining", f"{ep} · {t['param']}")])
                print(f"[*] ({i}/{len(targets)}) fuzzing {t['method']} {ep} · param "
                      f"'{t['param']}' (via {t.get('source', '?')})")
                tclient = HttpClient(base_url=t["url"], headers=hdrs,
                                     delay=args.delay, verify_tls=not args.insecure)
                topts = dict(opts, param=t["param"], method=t["method"], base_value=t["value"])
                before = len(report.findings)
                run_mods(param_mods, tclient, topts, tag=t["param"])
                # tag the new findings with which endpoint/param they came from
                for f in report.findings[before:]:
                    f.url, f.param, f.method = t["url"], t["param"], t["method"]
                    f.detail = f"[{t['method']} {ep} · {t['param']}] {f.detail}"
        else:
            print("[*] Param checks skipped (no -p and --no-crawl set)")

    # 3) Verification & light exploitation — grade confidence, extract proof, build PoCs
    headers = parse_headers(args.header)
    exploit_on = not args.no_exploit
    if exploit_on:
        print("[*] Verifying findings (confidence, proof extraction, PoC)…")
    for f in report.findings:
        f.remediation = f.remediation or exploit.REMEDIATION.get(f.check, "")
        # SQLi: actively extract the DB version as hard proof of exploitation
        if exploit_on and f.check == "sqli" and not f.proof and f.url and f.param:
            tc = HttpClient(base_url=f.url, headers=headers, delay=args.delay,
                            verify_tls=not args.insecure)

            def _send(pl, _tc=tc, _f=f):
                if (_f.method or "GET").upper() == "POST":
                    return _tc.request("POST", data={_f.param: pl}).body
                return _tc.request("GET", params={_f.param: pl}).body
            try:
                f.proof = exploit.extract_sqli(_send, "1")
            except Exception:
                pass
        f.poc = f.poc or exploit.poc_curl(f, headers)
        f.confidence = exploit.grade(f)

    report.print_console()

    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(report.to_json())
        print(f"\n[+] JSON report written to {args.json_out}")

    if args.html_out:
        import time
        meta = {
            "Target": f"{args.method} {args.url}",
            "Parameter": args.param or "(none)",
            "Checks run": ", ".join(m.NAME for m in mods),
            "Findings": str(len(report.findings)),
            "Generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        }
        with open(args.html_out, "w") as fh:
            fh.write(report.to_html(meta))
        print(f"[+] HTML report written to {args.html_out}")

    # exit non-zero if anything high/critical — handy for CI gating
    severe = [f for f in report.findings if f.severity in ("critical", "high")]
    sys.exit(1 if severe else 0)


if __name__ == "__main__":
    main()

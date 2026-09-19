# Authorized Web Pentest Toolkit (Rust)

A web application security scanner for **systems you own or are explicitly
authorized to test**. Detection-only, rate-limited, and dry-run by default.
One `pentest` binary covers black-box DAST checks, local source-code SAST,
real-CVE matching, and out-of-band (OOB) collaboration — no Python, no
runtime deps: `cargo build` produces two static binaries.

> ⚠️ Running these checks against systems you don't own or have written
> authorization to test is illegal in most jurisdictions. Don't.

## Build & install

```bash
cargo build --release
# scanner
./target/release/pentest --list-checks
# OOB collaborator listener (run on a host the TARGET can reach)
./target/release/collaborator --host 0.0.0.0 --port 9000
```

## Coverage

40 DAST check modules spanning the OWASP Top 10 and common web-attack
classes, plus 13 SAST rules (11 tree-sitter query rules — SQLi concat,
command exec/eval, unsafe deserialization, weak crypto, path traversal,
SSRF, open redirect, XSS sinks, disabled TLS verification, XPath/LDAP
injection, weak PRNGs — plus regex-based hardcoded-secret detection)
over Rust / TS / TSX / JS / Python source trees.

Every finding carries **standards refs** — the OWASP WSTG v4.2 test ID
(`WSTG-v42-INPV-05`-style, in the versioned form the WSTG asks tooling to
use), the CWE weakness, and, where iconic, the CAPEC attack pattern —
so a run's output drops straight into a PTES / NIST SP 800-115-style
report and WSTG coverage is auditable per check. Refs appear in JSON
findings, `--list-checks` output, and the console line:

| Module | Class | OWASP |
|--------|-------|-------|
| `recon`             | server/stack fingerprint, HTTP methods, TLS version & cert | A05/A06 |
| `api_docs`          | exposed Swagger/OpenAPI/Redoc contracts & UIs              | A05 |
| `debug_endpoints`   | Spring actuators, pprof, phpinfo, server-status, trace.axd | A05 |
| `tls_enum`          | TLS protocol-version enumeration (opt-in `--tls-enum`)     | A02     |
| `headers`           | security headers, cookie flags, CORS misconfig             | A05 |
| `content_discovery` | admin/api/backup path & directory enumeration              | A05 |
| `files`             | exposed .git/.env/backups, directory listing               | A05 |
| `sqli`              | error / boolean-blind / time-blind SQL injection           | A03 |
| `log4shell`         | JNDI lookup injection (Log4Shell), headers + params        | A06 |
| `nosqli`            | MongoDB operator & auth-bypass injection                   | A03 |
| `cmdi`              | OS command injection (in-band + time-blind)                | A03 |
| `ssti`              | server-side template injection                             | A03 |
| `traversal`         | path traversal / LFI (Unix + Windows + php filter)         | A01/A03 |
| `xxe`               | XML external entity file read                              | A05 |
| `crlf`              | CRLF injection / HTTP response splitting                   | A03 |
| `xss`               | reflected cross-site scripting                             | A03 |
| `dom_xss`           | DOM XSS (client JS source→sink analysis, no payloads)      | A03 |
| `ssrf`              | server-side request forgery (in-band + OOB callback)       | A10 |
| `redirect`          | open redirect                                              | A01 |
| `host_header`       | Host-header injection (reset/cache poisoning)              | A05 |
| `csrf`              | state-changing forms lacking anti-CSRF tokens             | A01 |
| `graphql`           | GraphQL introspection / IDE exposure                      | A05 |
| `jwt`               | JWT weakness analysis (alg=none, no exp, weak claims)     | A02/A07 |
| `info_disclosure`   | stack traces, debug pages, leaked keys/secrets            | A05/A09 |
| `idor`              | broken object-level authorization (heuristic)             | A01 |
| `hpp`               | HTTP parameter pollution (duplicate-param differential)   | A03 |
| `deserialize`       | unsafe deserialization error signatures (Java/PHP/.NET/pickle) | A08 |
| `business_logic`    | out-of-domain values (negative/zero/overflow) (opt-in `--logic`) | A04 |
| `ldap_injection`    | LDAP filter injection (auth bypass / error)               | A03 |
| `xpath_injection`   | XPath injection (error + boolean)                         | A03 |
| `cors_advanced`     | null/suffix/substring CORS trust bugs                     | A05 |
| `clickjacking`      | framable page (no XFO / frame-ancestors)                  | A05 |
| `method_tampering`  | TRACE/XST, WebDAV PUT, method-override bypass             | A05/A01 |
| `cache_deception`   | web cache deception on private pages                      | A05 |
| `secrets_in_js`     | API keys/tokens leaked in served JS bundles               | A05/A09 |
| `auth_bruteforce`   | username enumeration + missing rate-limit/lockout (opt-in)| A07 |
| `blind_oob`         | blind SSRF / stored XSS via a collaborator (opt-in)       | A10/A03 |
| `race_condition`    | concurrent duplicate-request consistency (opt-in `--race`) | A04 |
| `request_smuggling` | CL+TE / duplicate-CL framing probes (opt-in `--smuggling`) | A05 |
| `external`          | wraps installed sqlmap / nikto / nuclei (opt-in)          | — |

Run `pentest --list-checks` (human) or `pentest --list-checks --json`
(machine-readable, with each check's `site`/`param` kind).

## Layout

```
pentest/
├── src/main.rs            # `pentest` binary — CLI + orchestrator
├── crates/
│   ├── core/              # Finding, Severity, HttpClient (rate-limited), Report
│   ├── dast/              # 40 network checks + discovery + verify/exploit pass
│   ├── sast/              # tree-sitter source-code rule engine (--src)
│   ├── cve-lookup/        # OSV.dev + NVD matching, cvelistV5 record fetch
│   └── collaborator/      # `collaborator` binary — OOB listener
└── docs/superpowers/      # design spec + per-phase build plans
```

## Quick start

```bash
# 1. Dry run — prints the plan, sends nothing
pentest -u "https://staging.myapp.test/"

# 2. Full run — NO -p needed: it crawls links + forms and fuzzes every
#    parameter it finds. Pass -p only to target one parameter explicitly.
pentest -u "https://staging.myapp.test/" --confirm

# 2b. Explicit single parameter
pentest -u "https://staging.myapp.test/item?id=1" -p id --confirm

# 3. POST param, with auth, write JSON report
pentest -u "https://staging.myapp.test/search" -p q --method POST \
    -H "Cookie: session=abc" -H "Authorization: Bearer ..." \
    --confirm --json-out report.json

# 4. Static analysis of a local source tree (standalone, no target needed)
pentest --src ~/code/myapp

# 5. Both at once
pentest -u "https://staging.myapp.test/" --src ~/code/myapp --confirm
```

SAST reads local files only, so it is **not** gated behind `--confirm` —
that gate exists solely to stop unconfirmed requests reaching a target.

## Automatic attack-surface discovery

The injection checks (SQLi, XSS, SSTI, cmd, traversal, LDAP/XPath, IDOR, …) need
a parameter to fuzz. If you **don't** pass `-p`, the scanner actively maps the
target's surface, then fuzzes every parameter it finds. Findings are tagged with
the endpoint and parameter (and how it was discovered).

Discovery sources:
1. **Crawl** — follows same-origin links and parses `<form>` fields.
2. **robots.txt / sitemap.xml** — fetched and parsed for URLs (and their params).
3. **JavaScript bundles** — fetched and mined for API endpoints (`fetch("/api/…")`,
   quoted paths) and parameter names.
4. **Parameter mining** (Arjun-style) — brute-forces a wordlist of common param
   names against endpoints that expose none, detecting reflected / behavior-changing
   params. Discovered hidden params are reported as `info` findings.

Flags:
- `--crawl-pages N`  max pages to crawl (default 10)
- `--max-targets N`  max discovered params to fuzz (default 25)
- `--mine-params`    aggressive mining (brute more endpoints)
- `--no-mine`        disable hidden-param brute-forcing
- `--no-crawl`       disable discovery entirely (site-level + explicit `-p` only)

For safety it never crawls or fuzzes URLs whose path looks state-changing
(`logout`, `delete`, `remove`, `reset`, `checkout`, `pay`, …) and skips
CSRF-token/CAPTCHA fields.

## Agent / CI usage

`--json` is the machine-readable mode: stdout carries **only** the findings
array (same schema as `--json-out`), all human progress moves to stderr, and
exit codes are stable — built for driving from a script, CI job, or AI agent.

```bash
# Enumerate checks as JSON: [{"name":"recon","kind":"site"}, ...]
pentest --list-checks --json

# Scan and consume findings directly
pentest -u "https://staging.myapp.test/" --confirm --json | jq -r '.[] | select(.severity=="high" or .severity=="critical") | .title'

# Offline source audit, machine-readable
pentest --src ~/code/myapp --json
```

Exit codes:

- `0` — no high/critical findings
- `1` — at least one high/critical finding (use this to gate CI)
- `2` — usage error

A dry-run with `--json` still emits a valid (possibly empty) findings array,
so one command shape works with or without `--confirm`. Each finding object
carries `check`, `severity`, `title`, `detail`, `evidence`, `url`, `param`,
`method`, `payload`, `confidence` (`confirmed`/`firm`/`tentative`), `proof`,
`poc` (a replayable curl command), and `remediation`.

## Options

| Flag | Meaning |
|------|---------|
| `-u, --url`      | Target URL (include `?param=val` for GET) |
| `--src <dir>`    | Run the SAST pass against a local source tree |
| `-p, --param`    | Parameter to fuzz for SQLi / XSS / open-redirect |
| `--method`       | `GET` (default) or `POST` |
| `-H, --header`   | `Name: value` header, repeatable (auth cookies etc.) |
| `--delay`        | Seconds between requests (default 0.4 — be gentle) |
| `--sleep`        | Seconds for the time-based SQLi payload (default 5) |
| `--only a,b`      | Run only these checks |
| `--skip a,b`      | Skip these checks |
| `--list-checks`   | Print all check names and exit (`--json` for machine-readable) |
| `--ssrf-callback` | A URL you monitor, for out-of-band SSRF confirmation |
| `--collaborator`  | Base URL of a running `collaborator` listener for blind OOB checks |
| `--external`      | Also run installed `sqlmap`/`nikto`/`nuclei` |
| `--wordlist F`    | Extra paths for `content_discovery` (newline-delimited) |
| `--login-url`     | Login endpoint — enables `auth_bruteforce` |
| `--auth-username` | A real account you own (for the enumeration test) |
| `--user-field` / `--pass-field` | Login field names (default `username`/`password`) |
| `--auth-json`     | Send login as JSON instead of form |
| `--auth-attempts` | Bad-login attempts, max 5 (default 4) |
| `--race`          | Opt-in: concurrent duplicate-request burst (`race_condition`) |
| `--smuggling`     | Opt-in: request-smuggling framing probes (http targets) |
| `--logic`         | Opt-in: out-of-domain values on the target param (`business_logic`) |
| `--tls-enum`      | Opt-in: TLS version enumeration on https targets (`tls_enum`) |
| `--json`          | Findings array on stdout, progress on stderr (agent/CI mode) |
| `--html-out F`    | Write a standalone HTML report |
| `--no-exploit`    | Skip the verification/proof pass (detection only) |
| `--json-out F`    | Write findings as JSON to a file |
| `--confirm`       | Actually send requests (omit = dry run) |
| `--insecure`      | Disable TLS verification — **self-signed dev hosts only** |
| `--osv` / `--no-osv` | Real CVE matching via OSV.dev (default: on) |
| `--nvd-api-key`   | Enable NVD enrichment for infra/banner matches (default: off) |
| `--cve-dir <dir>` | Where CVE-schema records are written (default: `cve/`) |

## Verification & proof (finding weaknesses, not just probing)

After detection, a verification pass turns raw hits into confirmed weaknesses:

- **confidence** — every finding is graded `confirmed` / `firm` / `tentative`.
- **proof** — for SQLi it actively (read-only) extracts the **DB version** via
  error-based `extractvalue`/`updatexml`/cast payloads; LFI leaks a line of
  `/etc/passwd`; SSTI shows the evaluated expression; cmdi shows command output.
  Extraction never writes, deletes, or dumps user data — it reads one version
  string or public system file to prove impact.
- **PoC** — a reproducible `curl` command is generated for every parameterized
  finding, so you can replay it.
- **fix** — concrete remediation is attached per weakness class.

Disable the whole pass with `--no-exploit` (keeps detection only). Example line:

```
[CRITICAL] sqli (confirmed): Error-based SQL injection — [GET /product · id] … [WSTG-v42-INPV-05 · CWE-89 · CAPEC-66]
           PROOF : DBMS version extracted: 8.0.32-MariaDB (via extractvalue)
           PoC   : curl -sS 'http://host/product?id=1%27'
           fix   : Use parameterized queries / prepared statements; …
```

## CVE records & real-vulnerability matching

Every finding is also written to disk as its own record shaped like an official
CVE Record, under `--cve-dir` (default `cve/`), laid out like the real
`CVEProject/cvelistV5` repo: `cve/<YEAR>/<N>xxx/<ID>.json`. Self-discovered
findings use `PENTEST-LOCAL-<year>-<seq>` IDs — never a fabricated real-looking
CVE ID. When a check fingerprints a component/version (e.g. a server banner),
the toolkit queries **OSV.dev** (default on, `--no-osv` to disable) and
optionally **NVD** (`--nvd-api-key`), and a matched real CVE's actual record is
fetched verbatim from cvelistV5 with your detection context attached in an
`x_pentest` container.

## Blind / out-of-band checks (collaborator)

Blind SSRF and stored XSS produce no visible response — you confirm them when
the target calls back to a listener you control. The `collaborator` binary is a
tiny self-hosted alternative to Burp Collaborator (HTTP only, no DNS).

```bash
# 1. Run the collaborator on a host the TARGET can reach:
./target/release/collaborator --host 0.0.0.0 --port 9000

# 2. Point the scan at it:
pentest -u "https://staging.myapp.test/fetch?url=x" -p url --confirm \
    --collaborator http://YOUR_HOST:9000
```

`blind_oob` plants payloads, waits briefly, and polls the collaborator for hits.
Stored-XSS beacons may fire later (when an admin views the data) — leave the
collaborator running and watch its console (`[OOB HIT] token=…`). Hits are also
queryable: `GET /__hits/<token>` returns JSON.

## Login testing (auth_bruteforce)

Opt-in and **bounded to ≤5 attempts** — it never guesses real passwords, it only
sends a few deliberately-wrong logins to observe behavior (username enumeration
and whether repeated failures are throttled). Run against **your own** login.

```bash
pentest -u "https://staging.myapp.test/" --confirm \
    --login-url https://staging.myapp.test/api/login \
    --auth-username a-real-account@you.test \
    --user-field email --pass-field password --auth-json --auth-attempts 4
```

## HTML report

`--html-out FILE` writes a standalone, theme-aware HTML report (severity-colored,
target metadata, evidence). Combine with `--json-out` (or `--json`) for
machine-readable output.

```bash
pentest -u "https://staging.myapp.test/item?id=1" -p id --confirm \
    --html-out report.html --json-out report.json
```

## External tools

`--external` folds any installed `sqlmap`, `nikto`, and `nuclei` into the same
report (each bounded by a timeout). Missing tools are reported as info, not errors.

```bash
pentest -u "https://staging.myapp.test/item?id=1" -p id --confirm --external
```

## Not covered (needs a real DAST / manual testing)

Business-logic flaws beyond the `business_logic` out-of-domain heuristic,
second-order injection, full TLS cipher-suite enumeration, and real
deserialization gadget exploitation (`deserialize` detects error
signatures, it does not execute payloads). Stored/blind XSS is only
partially covered (via `blind_oob` + collaborator). Pair this with
`sqlmap`, OWASP ZAP, `nikto`, `nuclei`, and `testssl.sh`.

## Scope & safety notes

- **Detection only.** It never extracts data, writes, or deletes. Time-based
  SQLi payloads deliberately stall a response — run against **staging**, not prod.
- **Not exhaustive.** For a real audit also run `sqlmap`, `nikto`, and a proper
  DAST (OWASP ZAP). This toolkit is a fast first pass you can read and extend.
- **Remediation pointers** are printed with each finding class: parameterized
  queries for SQLi, output encoding + CSP for XSS, cookie flags, and security
  headers.

## Extending

Add a DAST check by dropping `crates/dast/src/checks/mycheck.rs` with:

```rust
use crate::opts::Opts;
use crate::registry::CheckFuture;
use pentest_core::{Finding, HttpClient, Severity};

pub const NAME: &str = "mycheck";

pub fn run<'a>(client: &'a HttpClient, _opts: &'a Opts) -> CheckFuture<'a> {
    Box::pin(async move {
        vec![Finding::new(NAME, Severity::Medium, "title", "detail").with_evidence("evidence")]
    })
}
```

then register it in `crates/dast/src/checks/mod.rs` and in the `SITE` or `PARAM`
list in `crates/dast/src/all.rs` (plus `ALL`). SAST rules are tree-sitter
`.scm`-style queries added to `crates/sast/src/query_rules.rs`.

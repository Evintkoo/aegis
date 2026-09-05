# Authorized Web Pentest Toolkit

A small, dependency-free (stdlib-only) web application security scanner for
**systems you own or are explicitly authorized to test**. Detection-only,
rate-limited, and dry-run by default.

> ⚠️ Running these checks against systems you don't own or have written
> authorization to test is illegal in most jurisdictions. Don't.

## Coverage

30 check modules spanning the OWASP Top 10 and common web-attack classes:

| Module | Class | OWASP |
|--------|-------|-------|
| `recon`             | server/stack fingerprint, HTTP methods, TLS version & cert | A05/A06 |
| `headers`           | security headers, cookie flags, CORS misconfig             | A05 |
| `content_discovery` | admin/api/backup path & directory enumeration              | A05 |
| `files`             | exposed .git/.env/backups, directory listing               | A05 |
| `sqli`              | error / boolean-blind / time-blind SQL injection           | A03 |
| `nosqli`            | MongoDB operator & auth-bypass injection                   | A03 |
| `cmdi`              | OS command injection (in-band + time-blind)                | A03 |
| `ssti`              | server-side template injection                             | A03 |
| `traversal`         | path traversal / LFI (Unix + Windows + php filter)         | A01/A03 |
| `xxe`               | XML external entity file read                              | A05 |
| `crlf`              | CRLF injection / HTTP response splitting                   | A03 |
| `xss`               | reflected cross-site scripting                             | A03 |
| `ssrf`              | server-side request forgery (in-band + OOB callback)       | A10 |
| `redirect`          | open redirect                                              | A01 |
| `host_header`       | Host-header injection (reset/cache poisoning)              | A05 |
| `csrf`              | state-changing forms lacking anti-CSRF tokens             | A01 |
| `graphql`           | GraphQL introspection / IDE exposure                      | A05 |
| `jwt`               | JWT weakness analysis (alg=none, no exp, weak claims)     | A02/A07 |
| `info_disclosure`   | stack traces, debug pages, leaked keys/secrets            | A05/A09 |
| `idor`              | broken object-level authorization (heuristic)             | A01 |
| `ldap_injection`    | LDAP filter injection (auth bypass / error)               | A03 |
| `xpath_injection`   | XPath injection (error + boolean)                         | A03 |
| `cors_advanced`     | null/suffix/substring CORS trust bugs                     | A05 |
| `clickjacking`      | framable page (no XFO / frame-ancestors)                  | A05 |
| `method_tampering`  | TRACE/XST, WebDAV PUT, method-override bypass             | A05/A01 |
| `cache_deception`   | web cache deception on private pages                      | A05 |
| `secrets_in_js`     | API keys/tokens leaked in served JS bundles               | A05/A09 |
| `auth_bruteforce`   | username enumeration + missing rate-limit/lockout (opt-in)| A07 |
| `blind_oob`         | blind SSRF / stored XSS via a collaborator (opt-in)       | A10/A03 |
| `external`          | wraps installed sqlmap / nikto / nuclei (opt-in)          | — |

## Layout

```
pentest/
├── run_all.py          # orchestrator — "run everything"
├── common.py           # HttpClient (rate-limited), Finding model, Report
├── checks/             # one file per check above (drop-in extensible)
└── README.md
```

`python3 run_all.py --list-checks` prints the live list.

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

There is also a richer standalone SQLi tool at `../sqli-test/sqli_test.py`
(more payloads + UNION column-count probe) for deep-diving a single parameter.

## Not covered (needs a real DAST / manual testing)

Insecure deserialization, race conditions, business-logic flaws, DOM XSS,
second-order injection, HTTP request smuggling, auth brute-force (deliberately
omitted to avoid lockout), and full TLS cipher enumeration. Stored/blind XSS is
only partially covered (via `blind_oob` + collaborator). Pair this with `sqlmap`,
OWASP ZAP, `nikto`, `nuclei`, and `testssl.sh`.

## Quick start

```bash
cd ~/pentest

# 1. Dry run — prints the plan, sends nothing
python3 run_all.py -u "https://staging.myapp.test/" 

# 2. Full run — NO -p needed: it crawls links + forms and fuzzes every
#    parameter it finds. Pass -p only to target one parameter explicitly.
python3 run_all.py -u "https://staging.myapp.test/" --confirm

# 2b. Explicit single parameter
python3 run_all.py -u "https://staging.myapp.test/item?id=1" -p id --confirm

# 3. POST param, with auth, write JSON report
python3 run_all.py -u "https://staging.myapp.test/search" -p q --method POST \
    -H "Cookie: session=abc" -H "Authorization: Bearer ..." \
    --confirm --json-out report.json
```

## Options

| Flag | Meaning |
|------|---------|
| `-u, --url`      | Target URL (include `?param=val` for GET) |
| `-p, --param`    | Parameter to fuzz for SQLi / XSS / open-redirect |
| `--method`       | `GET` (default) or `POST` |
| `-H, --header`   | `Name: value` header, repeatable (auth cookies etc.) |
| `--delay`        | Seconds between requests (default 0.4 — be gentle) |
| `--sleep`        | Seconds for the time-based SQLi payload (default 5) |
| `--only a,b`      | Run only these checks |
| `--skip a,b`      | Skip these checks |
| `--list-checks`   | Print all check names and exit |
| `--ssrf-callback` | A URL you monitor, for out-of-band SSRF confirmation |
| `--collaborator`  | Base URL of a running `collaborator.py` for blind OOB checks |
| `--external`      | Also run installed `sqlmap`/`nikto`/`nuclei` |
| `--wordlist F`    | Extra paths for `content_discovery` (newline-delimited) |
| `--login-url`     | Login endpoint — enables `auth_bruteforce` |
| `--auth-username` | A real account you own (for the enumeration test) |
| `--user-field` / `--pass-field` | Login field names (default `username`/`password`) |
| `--auth-json`     | Send login as JSON instead of form |
| `--auth-attempts` | Bad-login attempts, max 5 (default 4) |
| `--html-out F`    | Write a standalone HTML report |
| `--no-exploit`    | Skip the verification/proof pass (detection only) |
| `--json-out F`    | Write findings as JSON |
| `--confirm`       | Actually send requests (omit = dry run) |
| `--insecure`      | Disable TLS verification — **self-signed dev hosts only** |

Run `python3 run_all.py --list-checks` for the current check names.

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
[CRITICAL] sqli (confirmed): Error-based SQL injection — [GET /product · id] …
           PROOF : DBMS version extracted: 8.0.32-MariaDB (via extractvalue)
           PoC   : curl -sS 'http://host/product?id=1%27'
           fix   : Use parameterized queries / prepared statements; …
```

## Blind / out-of-band checks (collaborator)

Blind SSRF and stored XSS produce no visible response — you confirm them when
the target calls back to a listener you control. `collaborator.py` is a tiny
self-hosted alternative to Burp Collaborator (HTTP only, no DNS).

```bash
# 1. Run the collaborator on a host the TARGET can reach:
python3 collaborator.py --host 0.0.0.0 --port 9000

# 2. Point the scan at it:
python3 run_all.py -u "https://staging.myapp.test/fetch?url=x" -p url --confirm \
    --collaborator http://YOUR_HOST:9000
```

`blind_oob` plants payloads, waits briefly, and polls the collaborator for hits.
Stored-XSS beacons may fire later (when an admin views the data) — leave the
collaborator running and watch its console (`[OOB HIT] token=…`).

## Login testing (auth_bruteforce)

Opt-in and **bounded to ≤5 attempts** — it never guesses real passwords, it only
sends a few deliberately-wrong logins to observe behavior (username enumeration
and whether repeated failures are throttled). Run against **your own** login.

```bash
python3 run_all.py -u "https://staging.myapp.test/" --confirm \
    --login-url https://staging.myapp.test/api/login \
    --auth-username a-real-account@you.test \
    --user-field email --pass-field password --auth-json --auth-attempts 4
```

## HTML report

`--html-out FILE` writes a standalone, theme-aware HTML report (severity-colored,
target metadata, evidence). Combine with `--json-out` for machine-readable output.

```bash
python3 run_all.py -u "https://staging.myapp.test/item?id=1" -p id --confirm \
    --html-out report.html --json-out report.json
```

## External tools

`--external` folds any installed `sqlmap`, `nikto`, and `nuclei` into the same
report (each bounded by a timeout). Missing tools are reported as info, not errors.

```bash
python3 run_all.py -u "https://staging.myapp.test/item?id=1" -p id --confirm --external
```

## Exit codes

- `0` — no high/critical findings
- `1` — at least one high/critical finding (use this to gate CI)

## Scope & safety notes

- **Detection only.** It never extracts data, writes, or deletes. Time-based
  SQLi payloads deliberately stall a response — run against **staging**, not prod.
- **Not exhaustive.** For a real audit also run `sqlmap`, `nikto`, and a proper
  DAST (OWASP ZAP). This toolkit is a fast first pass you can read and extend.
- **Remediation pointers** are printed with each finding class:
  parameterized queries for SQLi, output encoding + CSP for XSS, cookie flags,
  and security headers.

## Extending

Add a new check by dropping `checks/mycheck.py` with:

```python
NAME = "mycheck"
def run(client, opts):        # client: HttpClient, opts: dict
    return [Finding(NAME, "medium", "title", "detail", "evidence")]
```

then register it in `checks/__init__.py`'s `ALL` list.

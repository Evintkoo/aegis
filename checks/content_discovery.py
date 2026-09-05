"""content_discovery — probe common sensitive paths / admin surfaces.

Broader directory enumeration than files.py (which targets specific leak files).
Flags paths that exist (200) or are protected-but-present (401/403). Optionally
pass opts['wordlist'] as a path to a newline-delimited list to extend coverage.
"""
import urllib.parse
from common import Finding

NAME = "content_discovery"

DEFAULT_PATHS = [
    "/admin", "/administrator", "/login", "/dashboard", "/api", "/api/v1", "/api/v2",
    "/graphql", "/swagger", "/swagger-ui.html", "/swagger.json", "/openapi.json",
    "/api-docs", "/actuator", "/actuator/health", "/actuator/env", "/metrics",
    "/health", "/status", "/debug", "/console", "/.git/", "/.svn/", "/backup",
    "/backups", "/old", "/dev", "/test", "/staging", "/config", "/uploads",
    "/private", "/internal", "/robots.txt", "/sitemap.xml", "/.well-known/",
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/server-status", "/.env",
]


def _load_wordlist(path):
    try:
        with open(path) as fh:
            return [("/" + l.strip().lstrip("/")) for l in fh if l.strip()]
    except Exception:
        return []


def run(client, opts):
    out = []
    parsed = urllib.parse.urlparse(client.base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    paths = list(DEFAULT_PATHS)
    if opts.get("wordlist"):
        paths += _load_wordlist(opts["wordlist"])

    # calibrate: what does a definitely-missing path return?
    ctrl = client.request("GET", url=root + "/zzq_definitely_missing_9182", allow_redirects=False)
    ctrl_status, ctrl_len = ctrl.status, len(ctrl.body)

    for p in paths:
        r = client.request("GET", url=root + p, allow_redirects=False)
        if r.status in (401, 403):
            out.append(Finding(NAME, "info", f"Protected resource present: {p}",
                               f"HTTP {r.status} — exists but access-controlled", p))
        elif r.status == 200 and not (r.status == ctrl_status and abs(len(r.body) - ctrl_len) < 30):
            sev = "medium" if any(s in p for s in
                                  ("admin", "actuator", "env", ".git", "backup", "phpmyadmin",
                                   "swagger", "debug", "console", "config")) else "low"
            out.append(Finding(NAME, sev, f"Reachable path: {p}",
                               f"HTTP 200 ({len(r.body)} bytes)", p))
    return out

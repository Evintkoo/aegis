"""secrets_in_js — fetch served JS bundles and scan for leaked keys/secrets."""
import re
import urllib.parse
from common import Finding

NAME = "secrets_in_js"

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']?([^"\'> ]+)', re.IGNORECASE)

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high", "Google API key"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical", "Stripe live secret key"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "critical", "Slack token"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"), "critical", "GitHub token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical", "Private key"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*"), "medium", "JWT"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
     "medium", "hard-coded credential assignment"),
    (re.compile(r"AIzaSy[A-Za-z0-9_\-]{33}"), "high", "Firebase/Google key"),
]


def run(client, opts):
    out = []
    r = client.request("GET")
    base = client.base_url

    srcs = SCRIPT_SRC_RE.findall(r.body)
    origin = urllib.parse.urlparse(base)
    same_origin = []
    for s in srcs:
        u = urllib.parse.urljoin(base, s)
        if urllib.parse.urlparse(u).netloc == origin.netloc:
            same_origin.append(u)

    scanned = 0
    seen = set()
    # scan inline scripts too (the base HTML itself)
    targets = [("inline HTML", r.body)]
    for u in same_origin[:15]:
        if u in seen:
            continue
        seen.add(u)
        try:
            jr = client.request("GET", url=u)
            targets.append((u, jr.body))
            scanned += 1
        except Exception:
            continue

    for where, text in targets:
        for pat, sev, label in SECRET_PATTERNS:
            for m in pat.finditer(text):
                masked = m.group(0)[:12] + "…"
                out.append(Finding(NAME, sev, f"{label} exposed in JS/HTML",
                                   f"found in {where}", masked))

    # de-dup
    uniq, keys = [], set()
    for f in out:
        k = (f.title, f.evidence)
        if k not in keys:
            keys.add(k)
            uniq.append(f)
    return uniq

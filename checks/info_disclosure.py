"""info_disclosure — verbose errors, stack traces, debug pages, leaked secrets."""
import re
from common import Finding

NAME = "info_disclosure"

STACK_MARKERS = {
    r"Traceback \(most recent call last\)": ("high", "Python stack trace"),
    r"at [\w.$]+\([\w.]+\.java:\d+\)": ("high", "Java stack trace"),
    r"You're seeing this error because you have DEBUG = True": ("high", "Django DEBUG page"),
    r"Whitespace-sensitive.*Rails|Action Controller: Exception caught": ("high", "Rails error page"),
    r"Fatal error:.*on line \d+": ("high", "PHP fatal error"),
    r"Warning: .* in .* on line \d+": ("medium", "PHP warning w/ path"),
    r"System\.\w+Exception:": ("high", ".NET exception"),
    r"ORA-\d{5}|SQLSTATE\[": ("medium", "DB error string"),
    r"node_modules|/var/www/|/home/\w+/|C:\\\\": ("low", "internal filesystem path leak"),
}

SECRET_COMMENT_RE = re.compile(
    r"<!--[^>]*(password|passwd|secret|api[_-]?key|todo|fixme|hack|xxx)[^>]*-->",
    re.IGNORECASE)
KEY_RE = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----|"
                    r"ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+)")


def _scan(body, out, where):
    for pat, (sev, label) in STACK_MARKERS.items():
        m = re.search(pat, body)
        if m:
            out.append(Finding(NAME, sev, f"{label} exposed",
                               f"verbose error/debug output in {where}", m.group(0)[:120]))
    for m in SECRET_COMMENT_RE.finditer(body):
        out.append(Finding(NAME, "low", "Suspicious HTML comment",
                           f"comment may leak info in {where}", m.group(0)[:120]))
    for m in KEY_RE.finditer(body):
        out.append(Finding(NAME, "critical", "Hard-coded credential/key in response",
                           f"secret pattern found in {where}", m.group(0)[:20] + "…"))


def run(client, opts):
    out = []
    seen = set()

    # 1) Baseline page
    r = client.request("GET")
    _scan(r.body, out, "base page")

    # 2) Force an error via a bogus path (verbose 404/500)
    root = client.base_url.split("?")[0].rstrip("/")
    err = client.request("GET", url=root + "/zzq_nonexistent_%27%22")
    _scan(err.body, out, "error page")

    # 3) Trigger via the fuzz param if provided
    param = opts.get("param")
    if param:
        method = opts.get("method", "GET").upper()
        bad = (client.request("GET", params={param: "'\"><"})
               if method == "GET" else client.request("POST", data={param: "'\"><"}))
        _scan(bad.body, out, f"param '{param}' error")

    # de-dup identical findings
    uniq = []
    for f in out:
        key = (f.title, f.evidence)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq

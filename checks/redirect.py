"""redirect — open-redirect probe on the injectable parameter.

Only meaningful when the target param feeds a redirect (next=, url=, return=…).
Checks whether an attacker-controlled absolute URL is honored in a 3xx Location.
"""
import urllib.parse
from common import Finding

NAME = "redirect"

EVIL = "https://evil.example.com/pwn"
# common redirect param names to also try opportunistically
COMMON = ["next", "url", "return", "returnTo", "redirect", "redirect_uri", "dest", "continue"]


def _check_param(client, param, method):
    payloads = [EVIL, "//evil.example.com/pwn", "/\\evil.example.com"]
    for pl in payloads:
        r = (client.request("GET", params={param: pl}, allow_redirects=False)
             if method == "GET" else client.request("POST", data={param: pl}, allow_redirects=False))
        loc = r.headers.get("Location", "")
        host = urllib.parse.urlparse(loc).netloc.lower()
        if "evil.example.com" in host or loc.startswith(("//evil", "/\\evil")):
            return pl, loc
    return None, None


def run(client, opts):
    out = []
    method = opts.get("method", "GET").upper()
    params = []
    if opts.get("param"):
        params.append(opts["param"])
    params += [p for p in COMMON if p != opts.get("param")]

    for param in params:
        pl, loc = _check_param(client, param, method)
        if loc:
            out.append(Finding(NAME, "medium", "Open redirect",
                               f"param '{param}' redirects off-site", f"{pl} -> {loc}"))
            break  # one confirmed is enough
    return out

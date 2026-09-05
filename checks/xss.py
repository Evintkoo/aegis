"""xss — reflected cross-site-scripting probe.

Injects unique markers and checks whether they come back unencoded in an
HTML-dangerous context. Detection only — never executes anything.
"""
import html
from common import Finding

NAME = "xss"

# Each marker is unique so we can confirm reflection unambiguously.
PROBES = [
    ("<zqx1>alert</zqx1>", "<zqx1>", "raw HTML tag reflected unencoded"),
    ("\"zqx2'>", "\"zqx2'>", "quote/angle-bracket breakout reflected unencoded"),
    ("javascript:zqx3", "javascript:zqx3", "reflected in a potential URL/js sink"),
]


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "XSS check skipped",
                        "no --param provided; specify a parameter to inject")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "test"))
    out = []

    for payload, needle, why in PROBES:
        val = base + payload
        r = (client.request("GET", params={param: val}) if method == "GET"
             else client.request("POST", data={param: val}))
        body = r.body
        # Reflected raw?  (encoded reflection is safe and ignored)
        if needle in body and html.escape(needle) not in body.replace(needle, "", 1):
            ctype = r.headers.get("Content-Type", "")
            if "html" in ctype.lower() or ctype == "":
                idx = body.find(needle)
                snippet = body[max(0, idx - 40):idx + len(needle) + 20]
                fnd = Finding(NAME, "high", "Reflected XSS",
                              f"{why} (param '{param}')", snippet.replace("\n", " "))
                fnd.payload = val
                out.append(fnd)
    return out

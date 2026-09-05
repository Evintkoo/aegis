"""crlf — CRLF injection / HTTP response splitting."""
from common import Finding

NAME = "crlf"

PAYLOADS = [
    "%0d%0aX-Crlf-Test: injected",
    "%0d%0aSet-Cookie: crlftest=1",
    "%E5%98%8A%E5%98%8DX-Crlf-Test: injected",   # unicode CR/LF trick
    "\r\nX-Crlf-Test: injected",
]


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "CRLF check skipped", "no --param provided")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "1"))
    out = []

    for p in PAYLOADS:
        val = base + p
        r = (client.request("GET", params={param: val}, allow_redirects=False)
             if method == "GET"
             else client.request("POST", data={param: val}, allow_redirects=False))
        lower = {k.lower(): v for k, v in r.headers.items()}
        if "x-crlf-test" in lower:
            out.append(Finding(NAME, "high", "CRLF injection / response splitting",
                               f"payload injected a response header via '{param}'", p))
            break
        if "crlftest" in lower.get("set-cookie", "").lower():
            out.append(Finding(NAME, "high", "CRLF injection (Set-Cookie)",
                               f"payload injected a Set-Cookie via '{param}'", p))
            break
    return out

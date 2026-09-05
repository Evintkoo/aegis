"""cache_deception — web cache deception on authenticated pages.

If a private page is also served (identically) under a fake static path like
/account/nonexistent.css AND the response looks cacheable, a CDN may cache the
victim's private page at a URL the attacker can then read. Most meaningful when
an auth header/cookie is supplied (-H).
"""
from common import Finding

NAME = "cache_deception"

STATIC_TRICKS = ["/nonexistent.css", "%2fnonexistent.css", "/nonexistent.js",
                 ";nonexistent.css", "/..%2fnonexistent.css"]


def _sim(a, b):
    if not a and not b:
        return 1.0
    m = max(len(a), len(b))
    return (min(len(a), len(b)) / m) if m else 1.0


def _cacheable(headers):
    cc = ""
    for k, v in headers.items():
        if k.lower() == "cache-control":
            cc = v.lower()
    if "no-store" in cc or "private" in cc:
        return False
    return "public" in cc or "max-age" in cc or cc == ""  # absent CC often => CDN default caches


def run(client, opts):
    out = []
    authed = bool(client.headers.get("Authorization") or client.headers.get("Cookie"))
    base = client.base_url.split("?")[0].rstrip("/")

    private = client.request("GET")
    if private.status >= 400:
        return out

    # Calibration: if a definitely-missing static path ALSO returns the private
    # body, the server just echoes everything — inconclusive, avoid false positive.
    cal = client.request("GET", url=base + "/zzq_missing_9182.css", allow_redirects=False)
    if cal.status == 200 and _sim(cal.body, private.body) > 0.9:
        return out

    for trick in STATIC_TRICKS:
        r = client.request("GET", url=base + trick, allow_redirects=False)
        # same private content served under a "static" URL?
        if r.status == 200 and _sim(r.body, private.body) > 0.9:
            if _cacheable(r.headers):
                sev = "high" if authed else "medium"
                out.append(Finding(NAME, sev, "Web cache deception",
                                   f"private page also served (cacheable) at '{trick}' — "
                                   f"a CDN may cache and expose it",
                                   f"{base + trick} -> HTTP 200, sim {_sim(r.body, private.body):.2f}"))
                return out
    return out

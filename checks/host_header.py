"""host_header — Host header injection (password-reset / cache poisoning surface)."""
from common import Finding

NAME = "host_header"

EVIL = "evil.example.com"


def run(client, opts):
    out = []

    # 1) Arbitrary Host accepted and reflected in body (absolute links / reset URLs)
    r = client.request("GET", extra_headers={"Host": EVIL})
    if EVIL in r.body:
        out.append(Finding(NAME, "high", "Host header reflected in response body",
                           "arbitrary Host echoed — password-reset poisoning risk",
                           f"Host: {EVIL}"))

    # 2) X-Forwarded-Host override reflected (common framework trust)
    r2 = client.request("GET", extra_headers={"X-Forwarded-Host": EVIL})
    if EVIL in r2.body:
        out.append(Finding(NAME, "high", "X-Forwarded-Host reflected in response",
                           "app trusts X-Forwarded-Host — reset/cache poisoning risk",
                           f"X-Forwarded-Host: {EVIL}"))

    # 3) Host injection in redirect Location
    r3 = client.request("GET", extra_headers={"Host": EVIL}, allow_redirects=False)
    loc = r3.headers.get("Location", "")
    if EVIL in loc:
        out.append(Finding(NAME, "high", "Host header controls redirect target",
                           "Location built from attacker Host", loc))

    # 4) Does the server even validate Host? (200 to a bogus Host)
    if not out and r.status < 400:
        out.append(Finding(NAME, "low", "Server accepts arbitrary Host header",
                           "no Host allow-listing (not reflected, but worth confirming vhosts)",
                           f"Host: {EVIL} -> HTTP {r.status}"))
    return out

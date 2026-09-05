"""clickjacking — page framable due to missing XFO and CSP frame-ancestors."""
import re
from common import Finding

NAME = "clickjacking"

FA_RE = re.compile(r"frame-ancestors", re.IGNORECASE)


def run(client, opts):
    out = []
    r = client.request("GET")
    lower = {k.lower(): v for k, v in r.headers.items()}
    ctype = lower.get("content-type", "")

    if "html" not in ctype.lower():
        return out  # only HTML pages are frameable in a meaningful way

    xfo = lower.get("x-frame-options", "").upper()
    csp = lower.get("content-security-policy", "")
    fa_protected = bool(FA_RE.search(csp))
    xfo_protected = xfo in ("DENY", "SAMEORIGIN")

    if not xfo_protected and not fa_protected:
        out.append(Finding(NAME, "medium", "Page is framable (clickjacking)",
                           "no X-Frame-Options and no CSP frame-ancestors — page can be "
                           "embedded in an attacker iframe for UI-redress attacks",
                           f"XFO={xfo or 'absent'}; frame-ancestors={'absent'}"))
    elif xfo and not xfo_protected and not fa_protected:
        out.append(Finding(NAME, "low", "Weak X-Frame-Options value",
                           f"XFO='{xfo}' is not DENY/SAMEORIGIN and is deprecated in favor of CSP",
                           xfo))
    return out

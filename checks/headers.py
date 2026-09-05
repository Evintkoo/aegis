"""headers — security-header audit, cookie flags, CORS misconfiguration."""
from common import Finding

NAME = "headers"

# header -> (severity if missing, human explanation)
EXPECTED = {
    "Content-Security-Policy": ("high", "no CSP — XSS/data-injection defense missing"),
    "Strict-Transport-Security": ("medium", "no HSTS — allows SSL-strip downgrade"),
    "X-Content-Type-Options": ("low", "missing nosniff — MIME-sniffing risk"),
    "X-Frame-Options": ("medium", "no clickjacking protection (also settable via CSP frame-ancestors)"),
    "Referrer-Policy": ("low", "no referrer policy — may leak URLs to third parties"),
}


def run(client, opts):
    out = []
    r = client.request("GET")
    lower = {k.lower(): v for k, v in r.headers.items()}

    for name, (sev, why) in EXPECTED.items():
        if name.lower() not in lower:
            out.append(Finding(NAME, sev, f"Missing {name}", why))

    # Cookie flags
    for k, v in r.headers.items():
        if k.lower() == "set-cookie":
            cl = v.lower()
            missing = []
            if "httponly" not in cl:
                missing.append("HttpOnly")
            if "secure" not in cl:
                missing.append("Secure")
            if "samesite" not in cl:
                missing.append("SameSite")
            if missing:
                cookie_name = v.split("=", 1)[0]
                out.append(Finding(NAME, "medium", f"Cookie '{cookie_name}' missing flags",
                                   f"absent: {', '.join(missing)}", v[:120]))

    # CORS reflection test — send an evil Origin, see if it's reflected
    evil = "https://evil.example.com"
    cr = client.request("GET", extra_headers={"Origin": evil})
    acao = cr.headers.get("Access-Control-Allow-Origin", "")
    acac = cr.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        out.append(Finding(NAME, "low", "CORS allows any origin",
                           "Access-Control-Allow-Origin: *", acao))
    elif acao == evil:
        sev = "high" if acac.lower() == "true" else "medium"
        out.append(Finding(NAME, sev, "CORS reflects arbitrary Origin",
                           f"reflected {evil}" + (" WITH credentials" if acac.lower() == "true" else ""),
                           f"ACAO={acao} ACAC={acac}"))
    return out

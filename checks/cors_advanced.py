"""cors_advanced — subtle CORS trust bugs beyond the basic headers check."""
import urllib.parse
from common import Finding

NAME = "cors_advanced"


def _origins(host):
    return [
        ("null", "null origin trusted (sandboxed iframe / data: URI can exploit)"),
        (f"https://{host}.evil.com", "suffix match — attacker subdomain of their own domain"),
        (f"https://evil{host}", "prefix/substring match bypass"),
        (f"https://{host}.evil-example.net", "arbitrary domain containing target host"),
        ("https://evil.example.com", "wholly arbitrary origin reflected"),
        (f"http://{host}", "insecure http origin trusted for an https site"),
    ]


def run(client, opts):
    out = []
    host = urllib.parse.urlparse(client.base_url).hostname or ""
    for origin, why in _origins(host):
        r = client.request("GET", extra_headers={"Origin": origin})
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == origin or (origin == "null" and acao == "null"):
            sev = "high" if acac == "true" else "medium"
            out.append(Finding(NAME, sev, "CORS reflects untrusted origin",
                               why + (" WITH credentials" if acac == "true" else ""),
                               f"Origin: {origin} -> ACAO={acao} ACAC={acac or 'unset'}"))
    return out

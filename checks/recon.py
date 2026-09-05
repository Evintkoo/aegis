"""recon — server fingerprint, HTTP methods, TLS certificate basics."""
import socket
import ssl
import urllib.parse
from common import Finding

NAME = "recon"

FINGERPRINT_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                       "X-AspNetMvc-Version", "X-Generator", "Via"]
RISKY_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


def _tls_info(host, port):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return ssock.version(), cert
    return None, None


def run(client, opts):
    out = []
    r = client.request("GET")

    # Fingerprinting via headers
    for h in FINGERPRINT_HEADERS:
        if h in r.headers:
            out.append(Finding(NAME, "info", f"{h} header exposed",
                               "reveals stack/version to attackers", r.headers[h]))

    # HTTP method probing
    try:
        opt = client.request("OPTIONS")
        allow = opt.headers.get("Allow", "")
        if allow:
            risky = [m for m in RISKY_METHODS if m in allow.upper()]
            sev = "medium" if risky else "info"
            out.append(Finding(NAME, sev, "Allowed HTTP methods",
                               f"OPTIONS advertises: {allow}"
                               + (f" — risky: {risky}" if risky else ""), allow))
    except Exception:
        pass

    # TLS cert basics
    parsed = urllib.parse.urlparse(client.base_url)
    if parsed.scheme == "https":
        host = parsed.hostname
        port = parsed.port or 443
        try:
            version, cert = _tls_info(host, port)
            if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                out.append(Finding(NAME, "medium", "Weak TLS version negotiated",
                                   f"server accepted {version}", version))
            else:
                out.append(Finding(NAME, "info", "TLS version", f"negotiated {version}", version))
            if cert and "notAfter" in cert:
                out.append(Finding(NAME, "info", "TLS certificate",
                                   f"expires {cert['notAfter']}",
                                   str(cert.get("subject", ""))))
        except Exception as e:
            out.append(Finding(NAME, "info", "TLS inspection failed", str(e)))
    return out

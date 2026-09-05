"""ssti — Server-Side Template Injection.

Uses arithmetic markers unlikely to collide with page content: if the template
engine evaluates the expression, the product appears in the response.
"""
from common import Finding

NAME = "ssti"

# (payload, expected rendered marker) — 31337*3 products are unique enough
PROBES = [
    ("{{31337*3}}", "94011"),                 # Jinja2 / Twig
    ("${31337*3}", "94011"),                  # FreeMarker / JSP EL / Mako
    ("#{31337*3}", "94011"),                  # Ruby / Thymeleaf
    ("<%= 31337*3 %>", "94011"),              # ERB / EJS
    ("${{31337*3}}", "94011"),                # nested
    ("*{31337*3}", "94011"),                  # Thymeleaf selection
    ("{31337*3}", "94011"),                   # Smarty
    ("#set($x=31337*3)$x", "94011"),          # Velocity
    ("{{= 31337*3 }}", "94011"),              # doT / underscore
    ("@(31337*3)", "94011"),                  # Razor
    ("{{'a'*3}}", "aaa"),                     # Jinja string mult (engine, not just math)
]


def _send(client, method, param, val):
    if method == "GET":
        return client.request("GET", params={param: val})
    return client.request("POST", data={param: val})


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "SSTI check skipped", "no --param provided")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "x"))
    out = []

    baseline = _send(client, method, param, base + "zzq")
    for payload, marker in PROBES:
        r = _send(client, method, param, base + payload)
        # rendered marker present AND raw payload NOT reflected verbatim => evaluated
        if marker in r.body and marker not in baseline.body and payload not in r.body:
            fnd = Finding(NAME, "critical", "Server-Side Template Injection",
                          f"payload {payload!r} evaluated to {marker!r}",
                          f"param '{param}' -> engine executed expression")
            fnd.payload = base + payload
            fnd.proof = f"expression {payload} evaluated server-side to {marker}"
            out.append(fnd)
            break
    return out

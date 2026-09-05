"""xpath_injection — XPath injection (error + boolean based)."""
import re
from common import Finding

NAME = "xpath_injection"

ERROR_MARKERS = re.compile(
    r"(XPathException|SimpleXMLElement|xmlXPathEval|Expression must evaluate|"
    r"MS\.Internal\.Xml|System\.Xml\.XPath|unexpected token in XPath|"
    r"Invalid expression|XPathEvalError)", re.IGNORECASE)

# (true, false) boolean pairs
BOOL_PAIRS = [("' or '1'='1", "' or '1'='2"),
              ("\" or \"1\"=\"1", "\" or \"1\"=\"2"),
              (" or 1=1 or ''='", " or 1=2 or ''='")]
ERROR_PAYLOADS = ["'", "\"", "']", "\"]", "' or name()='"]


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
        return [Finding(NAME, "info", "XPath-injection check skipped", "no --param provided")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "test"))
    out = []
    baseline = _send(client, method, param, base)

    for p in ERROR_PAYLOADS:
        r = _send(client, method, param, base + p)
        m = ERROR_MARKERS.search(r.body)
        if m and not ERROR_MARKERS.search(baseline.body):
            out.append(Finding(NAME, "high", "XPath injection (error-based)",
                               f"payload {p!r} triggered an XPath error", m.group(0)))
            return out

    for true_p, false_p in BOOL_PAIRS:
        t = _send(client, method, param, base + true_p)
        f = _send(client, method, param, base + false_p)
        if _sim(t.body, baseline.body) > 0.9 and _sim(t.body, f.body) < 0.85:
            out.append(Finding(NAME, "high", "XPath injection (boolean-based)",
                               f"{true_p!r} matched baseline, {false_p!r} diverged",
                               f"T/F sim={_sim(t.body, f.body):.2f}"))
            return out
    return out

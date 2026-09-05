"""csrf — detect state-changing forms lacking anti-CSRF tokens."""
import re
from common import Finding

NAME = "csrf"

FORM_RE = re.compile(r"(<form\b[^>]*>.*?</form>)", re.IGNORECASE | re.DOTALL)
METHOD_RE = re.compile(r'method\s*=\s*["\']?\s*post', re.IGNORECASE)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
TOKEN_RE = re.compile(
    r'name\s*=\s*["\']([^"\']*(csrf|token|nonce|authenticity|_token|xsrf)[^"\']*)["\']',
    re.IGNORECASE)


def run(client, opts):
    out = []
    r = client.request("GET")

    forms = FORM_RE.findall(r.body)
    for body in forms:
        is_post = bool(METHOD_RE.search(body))
        has_token = bool(TOKEN_RE.search(body))
        action = ACTION_RE.search(body)
        action_s = action.group(1) if action else "(same URL)"
        if is_post and not has_token:
            out.append(Finding(NAME, "medium", "POST form without anti-CSRF token",
                               f"form action={action_s} has no hidden CSRF token field",
                               body[:100].replace("\n", " ")))

    # Cookie SameSite as a secondary CSRF control
    for k, v in r.headers.items():
        if k.lower() == "set-cookie" and "samesite" not in v.lower():
            cookie = v.split("=", 1)[0]
            out.append(Finding(NAME, "low", f"Cookie '{cookie}' lacks SameSite",
                               "SameSite absent weakens CSRF defense-in-depth", v[:80]))
    return out

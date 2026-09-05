"""jwt — static analysis of any JWT found in request headers/cookies.

Detection-only: it inspects a token you already hold (via -H) and reports weak
algorithms, missing expiry, and sensitive claims. It does NOT forge tokens.
"""
import base64
import json as jsonlib
import re
import time
from common import Finding

NAME = "jwt"

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _find_tokens(headers):
    tokens = []
    for k, v in headers.items():
        for m in JWT_RE.findall(v):
            tokens.append((k, m))
    return tokens


def run(client, opts):
    out = []
    tokens = _find_tokens(client.headers)
    if not tokens:
        return [Finding(NAME, "info", "JWT check skipped",
                        "no JWT found in supplied headers (pass one via -H 'Authorization: Bearer ...')")]

    for src, tok in tokens:
        try:
            h_raw, p_raw, sig = tok.split(".")
            header = jsonlib.loads(_b64(h_raw))
            payload = jsonlib.loads(_b64(p_raw))
        except Exception:
            continue

        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            out.append(Finding(NAME, "critical", "JWT alg=none",
                               "token accepts unsigned 'none' algorithm", f"header={header}"))
        elif alg.startswith("hs"):
            out.append(Finding(NAME, "medium", "JWT uses symmetric HMAC (HS*)",
                               "verify the signing secret is strong & not guessable; "
                               "watch for RS256->HS256 confusion", f"alg={header.get('alg')}"))

        if "exp" not in payload:
            out.append(Finding(NAME, "medium", "JWT has no expiry (exp)",
                               "token never expires — stolen tokens valid forever", f"src={src}"))
        elif isinstance(payload["exp"], (int, float)) and payload["exp"] < time.time():
            out.append(Finding(NAME, "low", "JWT already expired",
                               "supplied token is past exp", f"exp={payload['exp']}"))

        sensitive = [k for k in payload if k.lower() in
                     ("password", "pwd", "secret", "ssn", "credit_card", "role", "is_admin", "admin")]
        if sensitive:
            out.append(Finding(NAME, "low", "JWT carries sensitive/authz claims in payload",
                               f"claims are base64 (not encrypted): {sensitive}", str(sensitive)))
    return out

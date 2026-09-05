"""idor — Broken access control / Insecure Direct Object Reference (heuristic).

Varies a numeric object id and checks whether *other* objects are returned,
and whether they are reachable WITHOUT the supplied auth. Heuristic — every
hit needs manual confirmation that the object belongs to another user.
"""
from common import Finding

NAME = "idor"


def _sim(a, b):
    if not a and not b:
        return 1.0
    m = max(len(a), len(b))
    return (min(len(a), len(b)) / m) if m else 1.0


def run(client, opts):
    param = opts.get("param")
    base = str(opts.get("base_value", ""))
    if not param or not base.isdigit():
        return [Finding(NAME, "info", "IDOR check skipped",
                        "needs a numeric --param value (e.g. ?id=42)")]
    method = opts.get("method", "GET").upper()
    n = int(base)
    out = []

    def fetch(val, with_auth=True):
        hdrs = None if with_auth else {"Authorization": "", "Cookie": ""}
        if method == "GET":
            return client.request("GET", params={param: str(val)},
                                  extra_headers=hdrs, allow_redirects=False)
        return client.request("POST", data={param: str(val)},
                              extra_headers=hdrs, allow_redirects=False)

    mine = fetch(n)
    others = [n - 1, n + 1, 1, 1000]
    accessible = []
    for o in others:
        if o == n or o < 0:
            continue
        r = fetch(o)
        # 200 with distinct-but-similar-shaped content => likely another user's object
        if r.status == 200 and 0.5 < _sim(r.body, mine.body) < 0.98 and r.body != mine.body:
            accessible.append(o)

    if len(accessible) >= 2:
        out.append(Finding(NAME, "high", "Possible IDOR / broken object-level authz",
                           f"objects {accessible} returned distinct content via '{param}' — "
                           f"confirm they belong to other users", f"ids={accessible}"))
        # escalate if reachable without auth too
        if client.headers.get("Authorization") or client.headers.get("Cookie"):
            noauth = fetch(accessible[0], with_auth=False)
            if noauth.status == 200 and len(noauth.body) > 0:
                out.append(Finding(NAME, "critical", "Object reachable WITHOUT authentication",
                                   f"id {accessible[0]} returned 200 with auth stripped",
                                   f"HTTP {noauth.status}"))
    return out

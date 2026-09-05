"""external — wrap installed industry tools (sqlmap / nikto / nuclei) and fold
their output into the same report.

Opt-in: only runs when opts['external'] is truthy. Detects tools on PATH; each
runs with a bounded timeout. These are slower and noisier than the built-in
checks — use for depth, not every run.
"""
import json
import re
import shutil
import subprocess
from common import Finding

NAME = "external"

TIMEOUT = 240  # seconds per tool


def _run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return p.stdout + "\n" + p.stderr
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") + "\n[external] TIMEOUT"
    except Exception as e:
        return f"[external] error: {e}"


def _sqlmap(url):
    out = []
    txt = _run(["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
                "--timeout", "15", "--disable-coloring", "--flush-session"])
    if re.search(r"is vulnerable|sqlmap identified the following injection", txt, re.I):
        params = re.findall(r"Parameter:\s*(\S+)", txt)
        out.append(Finding(NAME, "critical", "sqlmap confirmed SQL injection",
                           f"vulnerable parameter(s): {', '.join(params) or 'see output'}",
                           "sqlmap"))
    return out


def _nikto(url):
    out = []
    txt = _run(["nikto", "-h", url, "-maxtime", "120s", "-nointeractive", "-ask", "no"])
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("+ ") and any(w in line.lower() for w in
                                         ("osvdb", "outdated", "header", "vulnerab", "disclosure",
                                          "default", "cgi", "trace", "put", "index of")):
            out.append(Finding(NAME, "medium", "nikto finding", line[2:200], "nikto"))
    return out[:25]


def _nuclei(url):
    out = []
    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "info": "info", "unknown": "info"}
    txt = _run(["nuclei", "-u", url, "-silent", "-jsonl", "-timeout", "10"])
    for line in txt.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info", {})
        sev = sev_map.get(str(info.get("severity", "info")).lower(), "info")
        name = info.get("name") or d.get("template-id", "nuclei")
        out.append(Finding(NAME, sev, f"nuclei: {name}",
                           d.get("matched-at", d.get("host", url)),
                           d.get("template-id", "")))
    return out[:40]


TOOLS = {"sqlmap": _sqlmap, "nikto": _nikto, "nuclei": _nuclei}


def run(client, opts):
    if not opts.get("external"):
        return []  # opt-in; silent when not requested
    url = client.base_url
    out = []
    found_any = False
    for tool, fn in TOOLS.items():
        if shutil.which(tool):
            found_any = True
            print(f"    [external] running {tool} (up to {TIMEOUT}s)…")
            out.extend(fn(url))
        else:
            out.append(Finding(NAME, "info", f"{tool} not installed",
                               f"install {tool} to include it in the scan"))
    if not found_any:
        out.append(Finding(NAME, "info", "No external tools found",
                           "install sqlmap / nikto / nuclei on PATH to enable this check"))
    return out

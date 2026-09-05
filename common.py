"""
common.py — shared HTTP client, findings model, and reporting for the
authorized web pentest toolkit.

Every check module exposes:
    NAME = "short-name"
    def run(client: HttpClient, opts: dict) -> list[Finding]
"""

import copy
import json as jsonlib
import ssl
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict

# ---- Severity ordering -------------------------------------------------------
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    check: str          # which module produced it
    severity: str       # critical|high|medium|low|info
    title: str
    detail: str
    evidence: str = ""
    # --- enrichment (filled by the exploitation/verification pass) ---
    url: str = ""            # endpoint the finding is on
    param: str = ""          # injected parameter (if any)
    method: str = ""         # GET/POST
    payload: str = ""        # the payload that triggered it (if any)
    confidence: str = ""     # confirmed | firm | tentative
    proof: str = ""          # extracted proof (e.g. DB version) — hard evidence
    poc: str = ""            # reproducible curl command
    remediation: str = ""    # how to fix it

    def line(self):
        conf = f" ({self.confidence})" if self.confidence else ""
        return f"[{self.severity.upper():8}] {self.check}{conf}: {self.title} — {self.detail}"


@dataclass
class Response:
    status: int
    headers: dict
    body: str
    elapsed: float
    url: str


@dataclass
class HttpClient:
    base_url: str
    headers: dict = field(default_factory=dict)
    delay: float = 0.4
    timeout: int = 20
    verify_tls: bool = True
    _last: float = 0.0

    def _ctx(self):
        if self.verify_tls:
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request(self, method="GET", url=None, params=None, data=None,
                json=None, extra_headers=None, allow_redirects=True):
        # rate limit
        wait = self.delay - (time.perf_counter() - self._last)
        if wait > 0:
            time.sleep(wait)

        url = url or self.base_url
        if params:
            # Merge into (and OVERRIDE) any existing query params so an injected
            # value replaces the baseline instead of appending a duplicate.
            parsed = urllib.parse.urlparse(url)
            merged = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            merged.update({k: str(v) for k, v in params.items()})
            url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(merged)))

        hdrs = dict(self.headers)
        if extra_headers:
            hdrs.update(extra_headers)

        body = None
        if json is not None:
            body = jsonlib.dumps(json).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

        opener_handlers = []
        if not allow_redirects:
            opener_handlers.append(_NoRedirect())
        if not self.verify_tls:
            opener_handlers.append(urllib.request.HTTPSHandler(context=self._ctx()))
        opener = urllib.request.build_opener(*opener_handlers) if opener_handlers else None

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        start = time.perf_counter()
        try:
            do = opener.open if opener else urllib.request.urlopen
            with do(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
                out = Response(resp.status, dict(resp.headers), text,
                               time.perf_counter() - start, resp.geturl())
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            out = Response(e.code, dict(e.headers or {}), text,
                           time.perf_counter() - start, url)
        finally:
            self._last = time.perf_counter()
        return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # don't follow; surface the 3xx


class Report:
    def __init__(self):
        self.findings = []

    def add(self, findings):
        if findings:
            self.findings.extend(findings)

    def sorted(self):
        return sorted(self.findings, key=lambda f: SEV_ORDER.get(f.severity, 9))

    def print_console(self):
        print("\n" + "=" * 64)
        print(f"PENTEST REPORT — {len(self.findings)} finding(s)")
        print("=" * 64)
        if not self.findings:
            print("No findings. (Absence of evidence ≠ proof of safety.)")
            return
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = "  ".join(f"{k}={counts[k]}" for k in
                            sorted(counts, key=lambda s: SEV_ORDER.get(s, 9)))
        print(f"Summary: {summary}\n")
        for f in self.sorted():
            print(f.line())
            if f.evidence:
                ev = f.evidence if len(f.evidence) < 200 else f.evidence[:200] + "…"
                print(f"           evidence   : {ev}")
            if f.proof:
                print(f"           PROOF      : {f.proof}")
            if f.poc:
                print(f"           PoC        : {f.poc}")
            if f.remediation:
                print(f"           fix        : {f.remediation}")

    def to_json(self):
        return jsonlib.dumps([asdict(f) for f in self.sorted()], indent=2)

    def to_html(self, meta=None):
        import html as _html
        meta = meta or {}
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        colors = {"critical": "#b3123a", "high": "#d1451b", "medium": "#c98a00",
                  "low": "#2a7de1", "info": "#5c6672"}

        chips = "".join(
            f'<span class="chip" style="background:{colors.get(s, "#5c6672")}">'
            f'{s} {counts[s]}</span>'
            for s in sorted(counts, key=lambda x: SEV_ORDER.get(x, 9)))

        rows = ""
        for f in self.sorted():
            c = colors.get(f.severity, "#5c6672")
            conf = (f'<span class="conf">{_html.escape(f.confidence)}</span>'
                    if f.confidence else "")
            ev = f'<div class="lbl">evidence</div><pre>{_html.escape(f.evidence)}</pre>' if f.evidence else ""
            proof = (f'<div class="lbl proof">proof</div><pre class="proof">{_html.escape(f.proof)}</pre>'
                     if f.proof else "")
            poc = f'<div class="lbl">PoC</div><pre>{_html.escape(f.poc)}</pre>' if f.poc else ""
            fix = (f'<div class="fix"><b>Fix:</b> {_html.escape(f.remediation)}</div>'
                   if f.remediation else "")
            rows += (
                f'<tr><td><span class="sev" style="background:{c}">'
                f'{_html.escape(f.severity.upper())}</span>{conf}</td>'
                f'<td class="check">{_html.escape(f.check)}</td>'
                f'<td><div class="title">{_html.escape(f.title)}</div>'
                f'<div class="detail">{_html.escape(f.detail)}</div>{proof}{ev}{poc}{fix}</td></tr>')

        meta_rows = "".join(
            f'<tr><th>{_html.escape(str(k))}</th><td>{_html.escape(str(v))}</td></tr>'
            for k, v in meta.items())

        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#1a1d21;--mut:#5c6672;--bd:#e3e6ea}}
@media(prefers-color-scheme:dark){{:root{{--bg:#14171a;--card:#1d2125;--fg:#e7eaee;--mut:#9aa4af;--bd:#2c3238}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:2rem}}
.wrap{{max-width:1000px;margin:0 auto}}h1{{font-size:1.5rem;margin:0 0 .25rem}}
.sub{{color:var(--mut);margin:0 0 1.25rem}}
.chip,.sev{{color:#fff;border-radius:999px;padding:.15rem .6rem;font-size:.8rem;
font-weight:600;white-space:nowrap;display:inline-block}}
.chips{{margin:.75rem 0 1.5rem;display:flex;gap:.5rem;flex-wrap:wrap}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);
border-radius:10px;overflow:hidden}}
td,th{{padding:.7rem .8rem;text-align:left;vertical-align:top;border-top:1px solid var(--bd)}}
.meta{{margin-bottom:1.5rem}}.meta th{{color:var(--mut);width:130px;font-weight:500}}
.check{{color:var(--mut);font-family:ui-monospace,Menlo,monospace;font-size:.85rem;white-space:nowrap}}
.title{{font-weight:600}}.detail{{color:var(--mut);font-size:.9rem;margin-top:.15rem}}
.conf{{display:block;margin-top:.35rem;font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.03em}}
.lbl{{font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin:.55rem 0 .1rem}}
.lbl.proof{{color:#b3123a}}.fix{{font-size:.85rem;margin-top:.55rem;color:var(--fg)}}
pre{{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:.5rem .6rem;
margin:0;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-word}}
pre.proof{{border-color:#b3123a}}
.empty{{padding:2rem;text-align:center;color:var(--mut)}}
</style></head><body><div class="wrap">
<h1>Authorized Pentest Report</h1>
<p class="sub">Detection-only scan. Findings require manual confirmation.</p>
<table class="meta">{meta_rows}</table>
<div class="chips">{chips or '<span class="chip" style="background:#3aa76d">no findings</span>'}</div>
<table>{rows or '<tr><td class="empty">No findings — absence of evidence is not proof of safety.</td></tr>'}</table>
</div></body></html>"""

"""method_tampering — dangerous HTTP verbs, TRACE (XST), and override bypass.

Non-destructive: PUT/DELETE are aimed at a unique random path (never a real
resource), and any file created by a successful PUT is immediately DELETEd.
"""
import time
from common import Finding

NAME = "method_tampering"


def run(client, opts):
    out = []
    base = client.base_url.split("?")[0]
    root = base.rstrip("/")
    probe_path = f"{root}/pentest_probe_{int(time.time())}.txt"

    # 1) TRACE -> Cross-Site Tracing (echoes request, can leak headers/cookies)
    try:
        tr = client.request("TRACE", extra_headers={"X-Xst-Probe": "trace-canary-9182"})
        if "trace-canary-9182" in tr.body and tr.status < 400:
            out.append(Finding(NAME, "medium", "HTTP TRACE enabled (XST)",
                               "server echoes the request — enables Cross-Site Tracing",
                               tr.body[:80].replace("\n", " ")))
    except Exception:
        pass

    # 2) WebDAV PUT write (to a throwaway path), then clean up
    try:
        pr = client.request("PUT", url=probe_path, data=b"pentest-write-probe")
        if pr.status in (200, 201, 204):
            out.append(Finding(NAME, "high", "HTTP PUT allows file write (WebDAV)",
                               f"PUT created {probe_path} (HTTP {pr.status}) — remote file upload",
                               f"HTTP {pr.status}"))
            try:
                client.request("DELETE", url=probe_path)  # cleanup
            except Exception:
                out.append(Finding(NAME, "info", "Could not auto-delete PUT probe file",
                                   f"manually remove {probe_path}"))
    except Exception:
        pass

    # 3) Method-override header bypass (reach a method the WAF/route blocks)
    try:
        ov = client.request("POST",
                            extra_headers={"X-HTTP-Method-Override": "PUT",
                                           "X-HTTP-Method": "PUT"},
                            data=b"probe")
        base_get = client.request("GET")
        if ov.status < 400 and ov.status != base_get.status and ov.status not in (405, 501):
            out.append(Finding(NAME, "low", "Method-override header honored",
                               "X-HTTP-Method-Override changed handling — may bypass "
                               "method-based access controls", f"POST+override -> HTTP {ov.status}"))
    except Exception:
        pass
    return out

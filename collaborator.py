#!/usr/bin/env python3
"""
collaborator.py — a minimal out-of-band (OOB) interaction listener.

Run this on a host the TARGET server can reach. Any HTTP request it receives is
logged and bucketed by a token embedded in the path (/<token>/...). Blind-vuln
payloads point the target at http://<this-host>:<port>/<token>/... — when the
target's server (or a victim's browser, for blind XSS) fetches that URL, the hit
lands here and confirms the vulnerability.

Usage:
    python3 collaborator.py --host 0.0.0.0 --port 9000

Then in run_all:
    python3 run_all.py -u https://staging.myapp.test/... -p id --confirm \
        --collaborator http://YOUR_PUBLIC_HOST:9000

Query hits programmatically:  GET /__hits/<token>   -> JSON list (not logged)
This is a lightweight, self-hosted alternative to Burp Collaborator — HTTP only,
no DNS. Only expose it on infrastructure you control.
"""
import argparse
import json
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HITS = defaultdict(list)          # token -> [ {ts, method, path, headers, client} ]
START = time.time()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet; we print our own line

    def _record(self):
        path = self.path
        # Control endpoint: /__hits/<token> returns JSON and is NOT logged as a hit
        if path.startswith("/__hits/"):
            token = path[len("/__hits/"):].strip("/")
            body = json.dumps(HITS.get(token, [])).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Otherwise: log the interaction, bucket by first path segment (token)
        seg = path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        token = seg or "_"
        hit = {
            "ts": round(time.time() - START, 3),
            "method": self.command,
            "path": path,
            "headers": {k: v for k, v in self.headers.items()},
            "client": self.client_address[0],
        }
        HITS[token].append(hit)
        print(f"[OOB HIT] token={token} {self.command} {path} from {self.client_address[0]}")

        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record
    do_PUT = _record
    do_HEAD = _record
    do_OPTIONS = _record


def main():
    ap = argparse.ArgumentParser(description="OOB interaction collaborator server.")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[*] Collaborator listening on http://{args.host}:{args.port}")
    print(f"    Point blind payloads at http://<reachable-host>:{args.port}/<token>/")
    print(f"    Query hits: GET /__hits/<token>")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] shutting down")


if __name__ == "__main__":
    main()

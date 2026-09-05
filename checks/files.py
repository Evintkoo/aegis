"""files — probe for exposed sensitive files and directory listings."""
import urllib.parse
from common import Finding

NAME = "files"

# path -> (severity, why, content marker that confirms exposure)
SENSITIVE = {
    "/.git/HEAD": ("high", "exposed .git repository", "ref:"),
    "/.git/config": ("high", "exposed git config", "[core]"),
    "/.env": ("critical", "exposed environment file (secrets)", "="),
    "/.env.local": ("critical", "exposed local env file", "="),
    "/config.json": ("medium", "exposed config", "{"),
    "/wp-config.php.bak": ("critical", "backup of WP config", "DB_PASSWORD"),
    "/backup.sql": ("critical", "exposed SQL dump", "INSERT INTO"),
    "/.DS_Store": ("low", "macOS directory metadata leak", "Bud1"),
    "/phpinfo.php": ("high", "phpinfo() exposed", "PHP Version"),
    "/server-status": ("medium", "Apache server-status exposed", "Server Version"),
    "/actuator/env": ("high", "Spring Actuator env exposed", "propertySources"),
    "/.well-known/security.txt": ("info", "security.txt present (good practice)", "Contact"),
}


def run(client, opts):
    out = []
    parsed = urllib.parse.urlparse(client.base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for path, (sev, why, marker) in SENSITIVE.items():
        r = client.request("GET", url=root + path)
        if r.status == 200 and marker.lower() in r.body.lower():
            out.append(Finding(NAME, sev, f"Exposed {path}", why, r.body[:120]))

    # Directory listing check on root
    r = client.request("GET", url=root + "/")
    if "Index of /" in r.body or "<title>Directory listing" in r.body:
        out.append(Finding(NAME, "medium", "Directory listing enabled",
                           "server returns an auto-index page", "Index of /"))
    return out

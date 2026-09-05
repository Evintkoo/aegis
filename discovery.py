"""discovery.py — actively map a target's attack surface before fuzzing.

Beyond parsing forms, this module *fetches* to find hidden surface:
  1. crawl same-origin pages  -> links with params + form fields
  2. fetch robots.txt / sitemap.xml -> more URLs (and their params)
  3. fetch same-origin JS bundles   -> API endpoints + parameter names
  4. parameter mining (Arjun-style) -> brute a wordlist of common param names
     against endpoints that expose none, detecting reflected/behavior-changing
     params that are then handed to the injection checks.

Each target is {url, param, method, value, source}. Safety: never crawls or
fuzzes state-changing paths (logout/delete/reset/…) and skips token/CAPTCHA
fields.
"""
import re
import urllib.parse

LINK_RE = re.compile(r'<a\b[^>]+href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r'<script\b[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
FORM_RE = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
FORM_TAG_RE = re.compile(r'<form\b([^>]*)>', re.IGNORECASE)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
METHOD_RE = re.compile(r'method\s*=\s*["\']?\s*post', re.IGNORECASE)
INPUT_RE = re.compile(
    r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# JS mining: quoted absolute paths, and query strings embedded in JS
JS_PATH_RE = re.compile(r'["\'`](/[A-Za-z0-9_\-./]{2,80})(?=["\'`?\s])')
JS_QUERY_RE = re.compile(r'[?&]([A-Za-z0-9_\-]{1,40})=')
LOC_RE = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.IGNORECASE)
ROBOTS_RE = re.compile(r'^(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)', re.IGNORECASE | re.MULTILINE)

STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webp", ".map")
UNSAFE = re.compile(r"(logout|signout|sign-out|delete|remove|destroy|drop|"
                    r"deactivate|cancel|unsubscribe|reset|purge|checkout|pay)", re.IGNORECASE)
SKIP_FIELDS = re.compile(r"(csrf|token|nonce|authenticity|captcha|__viewstate)", re.IGNORECASE)

# Wordlist for parameter mining (compact, high-signal)
COMMON_PARAMS = [
    "id", "q", "s", "search", "query", "page", "p", "name", "user", "username",
    "email", "file", "path", "dir", "url", "uri", "redirect", "return", "next",
    "callback", "lang", "locale", "sort", "order", "filter", "category", "cat",
    "product", "item", "action", "view", "type", "key", "token", "ref", "code",
    "email", "message", "comment", "title", "slug", "year", "month", "limit", "offset",
]
CANARY = "zqx9182probe"


def _is_page(url):
    return not urllib.parse.urlparse(url).path.lower().endswith(STATIC_EXT)


def _mine_params(client, url, names, log):
    """Return param names that are 'honored' (reflected or change the response)."""
    try:
        base = client.request("GET", url=url)
    except Exception:
        return []
    if base.status >= 400:
        return []
    found = []
    for nm in names:
        try:
            r = client.request("GET", url=url, params={nm: CANARY})
        except Exception:
            continue
        if CANARY in r.body and CANARY not in base.body:
            found.append(nm)                                   # reflected -> processed
        elif r.status == base.status and abs(len(r.body) - len(base.body)) > 60:
            found.append(nm)                                   # behavior change
    return found


def discover(client, base_url, max_pages=10, max_targets=30, mine="auto", log=print):
    origin = urllib.parse.urlparse(base_url).netloc
    root = f"{urllib.parse.urlparse(base_url).scheme}://{origin}"
    targets, keys = [], set()
    js_urls, endpoints, js_params = set(), set(), set()
    seen_pages, queue = set(), [base_url]

    def add_target(url, param, method, value, source):
        if SKIP_FIELDS.search(param) or UNSAFE.search(url):
            return
        key = (url.split("?")[0], param, method)
        if key in keys:
            return
        keys.add(key)
        targets.append({"url": url, "param": param, "method": method,
                        "value": value or "1", "source": source})

    def note_url(u, source):
        pu = urllib.parse.urlparse(u)
        if pu.netloc != origin or not _is_page(u) or UNSAFE.search(u):
            return
        if pu.query:
            for k, v in urllib.parse.parse_qsl(pu.query, keep_blank_values=True):
                add_target(u, k, "GET", v, source)
        else:
            endpoints.add(u.split("#")[0])

    # --- 1) crawl same-origin pages ---
    while queue and len(seen_pages) < max_pages and len(targets) < max_targets:
        page = queue.pop(0)
        if page in seen_pages:
            continue
        seen_pages.add(page)
        try:
            r = client.request("GET", url=page)
        except Exception:
            continue
        if "html" not in r.headers.get("Content-Type", "").lower() and page != base_url:
            continue

        for src in SCRIPT_SRC_RE.findall(r.body):
            u = urllib.parse.urljoin(page, src)
            if urllib.parse.urlparse(u).netloc == origin and u.lower().endswith(".js"):
                js_urls.add(u)

        for href in LINK_RE.findall(r.body):
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            u = urllib.parse.urljoin(page, href)
            pu = urllib.parse.urlparse(u)
            if pu.netloc != origin or not _is_page(u) or UNSAFE.search(u):
                continue
            if pu.query:
                note_url(u, "link")
            elif u not in seen_pages and u not in queue \
                    and len(seen_pages) + len(queue) < max_pages:
                queue.append(u)
                endpoints.add(u.split("#")[0])

        for form in FORM_RE.findall(r.body):
            tag = FORM_TAG_RE.search(form)
            attrs = tag.group(1) if tag else ""
            method = "POST" if METHOD_RE.search(attrs) else "GET"
            am = ACTION_RE.search(attrs)
            action = urllib.parse.urljoin(page, am.group(1)) if am and am.group(1) else page
            if urllib.parse.urlparse(action).netloc != origin or UNSAFE.search(action):
                continue
            for name in INPUT_RE.findall(form):
                add_target(action, name, method, "test", "form")

    # --- 2) robots.txt + sitemap.xml ---
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            rr = client.request("GET", url=root + path)
        except Exception:
            continue
        if rr.status != 200:
            continue
        if path.endswith(".xml"):
            for loc in LOC_RE.findall(rr.body)[:100]:
                note_url(loc.strip(), "sitemap")
        else:
            for m in ROBOTS_RE.findall(rr.body):
                note_url(urllib.parse.urljoin(root, m), "robots")

    # --- 3) fetch JS bundles -> endpoints + param names ---
    for ju in list(js_urls)[:12]:
        try:
            jr = client.request("GET", url=ju)
        except Exception:
            continue
        for p in JS_PATH_RE.findall(jr.body):
            u = urllib.parse.urljoin(root, p)
            if _is_page(u) and not UNSAFE.search(u) \
                    and urllib.parse.urlparse(u).netloc == origin:
                endpoints.add(u.split("?")[0].split("#")[0])
        for nm in JS_QUERY_RE.findall(jr.body):
            js_params.add(nm)

    # --- 4) parameter mining on paramless endpoints ---
    if mine != "off":
        # JS-derived names first (target-specific, higher signal), then common.
        wordlist = list(dict.fromkeys(list(js_params) + COMMON_PARAMS))[:45]
        # bound how many endpoints we brute
        cap = 12 if mine == "aggressive" else 4
        to_mine = [base_url] + sorted(e for e in endpoints if "?" not in e)
        seen_mine = set()
        mined_count = 0
        for url in to_mine:
            if mined_count >= cap:
                break
            key = url.split("?")[0]
            if key in seen_mine:
                continue
            seen_mine.add(key)
            mined_count += 1
            for nm in _mine_params(client, url, wordlist, log):
                add_target(url, nm, "GET", CANARY, "mined")

    # --- summary ---
    by_src = {}
    for t in targets:
        by_src[t["source"]] = by_src.get(t["source"], 0) + 1
    src_str = ", ".join(f"{k}:{v}" for k, v in sorted(by_src.items())) or "none"
    log(f"[*] Discovery: {len(targets)} param(s) [{src_str}] across "
        f"{len({t['url'].split('?')[0] for t in targets})} endpoint(s); "
        f"crawled {len(seen_pages)} page(s), {len(js_urls)} JS file(s), "
        f"{len(endpoints)} endpoint(s) mapped")
    return targets[:max_targets]

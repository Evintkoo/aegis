"""auth_bruteforce — user enumeration & missing rate-limit / lockout (opt-in).

SAFETY: this never guesses real passwords (no wordlist). It only sends a small,
bounded number of *deliberately wrong* logins to observe the app's behavior:
  • user enumeration — does a valid username respond differently from a bogus one?
  • missing rate limiting / lockout — are repeated bad logins throttled at all?

Opt-in: requires opts['login_url'] + opts['auth_username']. Attempts are capped
at 5 to avoid locking out the account. Run only against your own login.
"""
import re
from common import Finding

NAME = "auth_bruteforce"

LOCKOUT_RE = re.compile(
    r"(too many|rate limit|locked|lockout|try again later|captcha|"
    r"temporarily (disabled|blocked)|slow down|429)", re.IGNORECASE)
NOUSER_RE = re.compile(
    r"(no such user|user (not found|does not exist)|unknown (user|account)|"
    r"invalid username|account not found|email not (found|registered))", re.IGNORECASE)


def _sim(a, b):
    if not a and not b:
        return 1.0
    m = max(len(a), len(b))
    return (min(len(a), len(b)) / m) if m else 1.0


def _login(client, opts, user, pw):
    url = opts["login_url"]
    uf = opts.get("user_field", "username")
    pf = opts.get("pass_field", "password")
    if opts.get("auth_json"):
        return client.request("POST", url=url, json={uf: user, pf: pw})
    return client.request("POST", url=url, data={uf: user, pf: pw})


def run(client, opts):
    if not (opts.get("login_url") and opts.get("auth_username")):
        return []  # opt-in; silent when not configured
    out = []
    valid_user = opts["auth_username"]
    bogus_user = "zzq_nouser_9182_%s" % valid_user[:4]
    wrong_pw = "definitely_wrong_pw_9182!"
    attempts = min(int(opts.get("auth_attempts", 4)), 5)

    # --- 1) User enumeration -------------------------------------------------
    r_valid = _login(client, opts, valid_user, wrong_pw)
    r_bogus = _login(client, opts, bogus_user, wrong_pw)

    if NOUSER_RE.search(r_bogus.body) and not NOUSER_RE.search(r_valid.body):
        out.append(Finding(NAME, "medium", "Username enumeration (distinct error message)",
                           "bogus username yields a 'no such user' message that a valid "
                           "username does not — attackers can enumerate accounts",
                           NOUSER_RE.search(r_bogus.body).group(0)))
    elif r_valid.status != r_bogus.status or _sim(r_valid.body, r_bogus.body) < 0.9:
        out.append(Finding(NAME, "low", "Possible username enumeration (response differs)",
                           f"valid vs bogus username differ (HTTP {r_valid.status} vs "
                           f"{r_bogus.status}, sim {_sim(r_valid.body, r_bogus.body):.2f}) — verify",
                           f"{r_valid.status}/{r_bogus.status}"))
    elif r_valid.elapsed > r_bogus.elapsed + 0.4:
        out.append(Finding(NAME, "low", "Possible timing-based username enumeration",
                           f"valid username is slower ({r_valid.elapsed:.2f}s vs "
                           f"{r_bogus.elapsed:.2f}s) — password hashing only runs for real users",
                           f"{r_valid.elapsed:.2f}s vs {r_bogus.elapsed:.2f}s"))

    # --- 2) Missing rate limiting / lockout ----------------------------------
    throttled = False
    for i in range(attempts):
        r = _login(client, opts, valid_user, wrong_pw + str(i))
        if r.status == 429 or LOCKOUT_RE.search(r.body):
            throttled = True
            break
    if not throttled:
        out.append(Finding(NAME, "medium", "No rate limiting / account lockout on login",
                           f"{attempts} bad logins for '{valid_user}' were all accepted without "
                           "a 429, CAPTCHA, or lockout — enables credential brute-forcing",
                           f"{attempts} attempts, no throttle"))
    return out

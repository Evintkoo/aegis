"""Check modules for the authorized pentest toolkit."""
from . import (
    recon, headers, content_discovery, files,
    sqli, nosqli, cmdi, ssti, traversal, xxe, crlf, xss,
    ldap_injection, xpath_injection,
    ssrf, redirect, host_header, csrf, cors_advanced, clickjacking,
    method_tampering, cache_deception, graphql, jwt,
    info_disclosure, secrets_in_js, idor,
    auth_bruteforce, blind_oob, external,
)

# Order = execution order in run_all.
# recon/discovery -> injections -> logic/config -> disclosure -> opt-in (auth, OOB, external)
ALL = [
    recon, headers, content_discovery, files,
    sqli, nosqli, cmdi, ssti, traversal, xxe, crlf, xss,
    ldap_injection, xpath_injection,
    ssrf, redirect, host_header, csrf, cors_advanced, clickjacking,
    method_tampering, cache_deception, graphql, jwt,
    info_disclosure, secrets_in_js, idor,
    auth_bruteforce, blind_oob, external,
]

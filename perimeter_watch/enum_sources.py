"""Subdomain enumeration sources, all injectable for tests.

CT_SOURCE: certificate transparency via crt.sh (HTTPS, JSON).
"""
import json
import urllib.request


def ct_subdomains(domain, timeout=15, endpoint="https://crt.sh"):
    """Query crt.sh for subdomains issued certificates for `domain`.

    Returns a sorted set of subdomain names. Failures raise RuntimeError
    with the reason — the caller decides how loud to be.
    """
    url = f"{endpoint}/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "perimeter-watch/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            rows = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"crt.sh query failed: {error}") from error

    found = set()
    for row in rows:
        for name in (row.get("name_value") or "").splitlines():
            name = name.strip().lower().rstrip(".")
            if name.endswith("." + domain) and "*" not in name:
                found.add(name)
    return sorted(found)

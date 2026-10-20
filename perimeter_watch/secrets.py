"""Secret exposure scanning on scoped assets — read-only GETs only.

Two checks per scoped base URL: sensitive public files that should
never be reachable (/.git/HEAD, /.env, ...) and secret-shaped
patterns in fetched bodies. Never posts anything anywhere.
"""
import re
import urllib.request

SENSITIVE_PATHS = ["/.git/HEAD", "/.git/config", "/.env", "/config.json.bak"]

PATTERNS = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret key assignment", re.compile(r"aws_secret_access_key\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.I)),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("MongoDB connection string", re.compile(r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@")),
]


def fetch(url, timeout=10):
    """Fetch a URL read-only; returns (status, body) or (0, error)."""
    req = urllib.request.Request(url, headers={"User-Agent": "perimeter-watch/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read(500_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, ""
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return 0, str(error)


def scan_asset(base_url, fetch_fn=None):
    """Scan one base URL. Returns a list of exposure findings."""
    fetch_fn = fetch_fn or fetch
    findings = []

    for path in SENSITIVE_PATHS:
        status, body = fetch_fn(base_url.rstrip("/") + path)
        if status == 200 and body:
            findings.append({
                "kind": "sensitive-file",
                "url": base_url.rstrip("/") + path,
                "evidence": f"{path} is publicly readable (HTTP 200, {len(body)}B)",
            })

    _, body = fetch_fn(base_url.rstrip("/") + "/")
    if body and "unreachable" not in body[:50]:
        for label, pattern in PATTERNS:
            match = pattern.search(body)
            if match:
                findings.append({
                    "kind": "secret-pattern",
                    "url": base_url.rstrip("/") + "/",
                    "evidence": f"{label} found in page body",
                    "excerpt": match.group(0)[:24] + "…",
                })
    return findings


def scan_all(base_urls, fetch_fn=None):
    """Scan every base URL; returns {url: [findings]}."""
    return {url: scan_asset(url, fetch_fn=fetch_fn) for url in base_urls}

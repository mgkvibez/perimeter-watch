"""Exposed cloud-storage detection: anonymous listing = exposed bucket.

Scope: read-only GET listing probes against storage-shaped targets
derived from your own assets (S3/Azure Blob/GCS CNAMEs and hosts).
A bucket that answers an anonymous listing request with content is
an exposure — anyone can enumerate its files.
"""
from urllib.request import Request, urlopen
from urllib.error import URLError

PROVIDERS = {
    "s3": {
        "match": ("s3.amazonaws.com", "s3.", ".s3."),
        "list_path": "/?list-type=2&max-keys=1",
        "marker": "<ListBucketResult",
    },
    "azure": {
        "match": ("blob.core.windows.net", ".blob.core", "dfs.core.windows.net"),
        "list_path": "/?$container&restype=container&comp=list&maxresults=1",
        "marker": "<EnumerationResults",
    },
    "gcs": {
        "match": ("storage.googleapis.com", ".storage.googleapis.com",),
        "list_path": "?max-results=1",
        "marker": "<ListBucketResult",
    },
}


def detect_storage_targets(records):
    """Yield (name, provider, base_url) for storage-shaped assets."""
    for name, rec in records.items():
        if not rec:
            continue
        aliases = [a.lower() for a in (rec.get("aliases") or [])]
        candidates = [rec.get("cname", "").lower()] + aliases
        for provider, spec in PROVIDERS.items():
            for cand in candidates:
                if cand and any(m in cand for m in spec["match"]):
                    proto = "https"
                    base = f"{proto}://{cand.rstrip('.')}"
                    yield name, provider, base
                    break


def _fetch(base, list_path, fetch):
    url = base.rstrip("/") + list_path
    if fetch is not None:
        return fetch(url)
    try:
        req = Request(url, headers={"User-Agent": "perimeter-watch/0.3"})
        with urlopen(req, timeout=15) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace")
    except URLError:
        return None, ""


def probe(base, provider, fetch=None):
    """Return True if the target allows anonymous listing."""
    spec = PROVIDERS[provider]
    status, body = _fetch(base, spec["list_path"], fetch)
    return bool(status == 200 and spec["marker"] in body)


def scan_buckets(records, fetch=None):
    """Scan storage-shaped targets for anonymous listing exposure.

    Returns a list of exposure dicts: name, provider, target, evidence.
    """
    exposures = []
    seen = set()
    for name, provider, base in detect_storage_targets(records):
        if (name, base) in seen:
            continue
        seen.add((name, base))
        try:
            if probe(base, provider, fetch=fetch):
                exposures.append({
                    "name": name,
                    "provider": provider,
                    "target": base,
                    "evidence": f"anonymous listing allowed ({provider} list API)",
                })
        except Exception:
            continue
    return exposures

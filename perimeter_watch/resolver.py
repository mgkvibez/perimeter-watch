"""DNS resolution via the standard library.

gethostbyname_ex returns (hostname, aliaslist, ipaddrlist) — the alias
list carries the CNAME chain, which is what takeover detection needs.
"""
import socket


def resolve(name, timeout=5):
    """Resolve a name; return a record dict or None if unresolvable."""
    try:
        _name, aliases, ips = socket.gethostbyname_ex(name)
    except (socket.gaierror, TimeoutError, OSError):
        return None
    return {
        "name": name,
        "aliases": [a.lower() for a in aliases],
        "ips": sorted(ips),
    }


def resolve_all(names):
    """Resolve every name; returns {name: record-or-None}."""
    return {name: resolve(name) for name in names}

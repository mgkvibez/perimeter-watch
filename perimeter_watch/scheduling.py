"""Multi-domain scan scheduling with per-domain intervals and due-status checks."""
import datetime as dt

DEFAULT_INTERVAL_DAYS = 7


def parse_watchlist_domains(watchlist):
    """Parse domain entries from watchlist.

    Supports domain strings (e.g. "example.com") or objects
    (e.g. {"domain": "example.com", "interval_days": 3} or {"name": "example.com"}).
    Returns a list of dicts: [{"name": str, "interval_days": float}, ...].
    """
    raw_domains = watchlist.get("domains", [])
    default_interval = watchlist.get("default_interval_days", DEFAULT_INTERVAL_DAYS)
    result = []
    for item in raw_domains:
        if isinstance(item, str):
            result.append({"name": item, "interval_days": float(default_interval)})
        elif isinstance(item, dict):
            name = item.get("domain") or item.get("name")
            if name:
                interval = item.get("interval_days", default_interval)
                result.append({"name": name, "interval_days": float(interval)})
    return result


def get_domain_due_status(domain_config, last_scanned_iso, now=None):
    """Check if a single domain is due for scanning.

    now: dt.datetime or callable returning dt.datetime or None (defaults to UTC now).
    Returns (is_due: bool, reason: str, elapsed_days: float or None).
    """
    if now is None:
        current_time = dt.datetime.now(dt.timezone.utc)
    elif callable(now):
        current_time = now()
    else:
        current_time = now

    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=dt.timezone.utc)

    name = domain_config["name"]
    interval = domain_config["interval_days"]

    if not last_scanned_iso:
        return True, f"never scanned before (interval: {interval:g}d)", None

    try:
        last_dt = dt.datetime.fromisoformat(last_scanned_iso)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=dt.timezone.utc)
    except (ValueError, TypeError):
        return True, f"invalid last_scanned timestamp ({last_scanned_iso})", None

    elapsed = (current_time - last_dt).total_seconds() / 86400.0
    if elapsed < 0:
        # Clock skew / future timestamp
        return True, f"last_scanned in future ({elapsed:.1f}d), scanning now", elapsed

    if elapsed >= interval:
        return True, f"last scanned {elapsed:.1f}d ago >= {interval:g}d interval", elapsed
    else:
        remaining = interval - elapsed
        return False, f"last scanned {elapsed:.1f}d ago < {interval:g}d interval (due in {remaining:.1f}d)", elapsed


def evaluate_due_domains(watchlist, last_scanned_map, now=None):
    """Evaluate due status for all domains in watchlist.

    Returns a list of dicts with domain metadata, due flag, and reason.
    """
    domains = parse_watchlist_domains(watchlist)
    evaluations = []
    for d in domains:
        name = d["name"]
        last_ts = (last_scanned_map or {}).get(name)
        is_due, reason, elapsed = get_domain_due_status(d, last_ts, now=now)
        evaluations.append({
            "name": name,
            "interval_days": d["interval_days"],
            "last_scanned": last_ts,
            "due": is_due,
            "reason": reason,
            "elapsed_days": elapsed,
        })
    return evaluations

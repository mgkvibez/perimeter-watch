"""Snapshot state + diff engine, persisted as JSON."""
import json
from pathlib import Path


def load_state(path):
    """Load the previous snapshot, unwrapping the persisted envelope."""
    path = Path(path)
    if not path.exists():
        return {}
    state = json.loads(path.read_text(encoding="utf-8"))
    if "captured_at" in state and isinstance(state.get("domains"), dict):
        return state["domains"]
    return state


def save_state(state, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def diff(previous, current):
    """Diff two snapshots: {domain: {name: record-or-None}}.

    Returns per-domain changes: added names, removed names, changed
    records (IP or alias moves), and newly-dangling names.
    """
    report = {}
    for domain, records in current.items():
        before = previous.get(domain, {})
        added = sorted(set(records) - set(before))
        removed = sorted(set(before) - set(records))

        changed = []
        for name in sorted(set(records) & set(before)):
            if _canon(records[name]) != _canon(before[name]):
                changed.append(name)

        # A name is newly dangling only if it resolved before and
        # no longer does. A first-seen unresolvable name is normal
        # (cert issued, DNS never configured) — that is not a regression.
        newly_dangling = [
            n for n in sorted(set(records) & set(before))
            if records[n] is None and before[n] is not None
        ]

        report[domain] = {
            "added": added,
            "removed": removed,
            "changed": changed,
            "newly_dangling": newly_dangling,
            "total": len(records),
        }
    return report


def _canon(record):
    if record is None:
        return None
    return (tuple(record["aliases"]), tuple(record["ips"]))

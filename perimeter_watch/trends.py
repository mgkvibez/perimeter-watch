"""Historical trend reports from the per-run history journal.

run() appends one JSON line per run to history.jsonl; this module
turns that journal into a trend report: asset growth, exposure
incidents, and per-week deltas.
"""
import datetime as dt
import json
from pathlib import Path


def append_history(history_path, entry):
    """Append one run summary line to the journal."""
    p = Path(history_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def load_history(history_path):
    """Load the journal, tolerating corrupt lines."""
    p = Path(history_path)
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def summarize(history):
    """Aggregate the journal into a trend summary."""
    if not history:
        return {"runs": 0}
    runs = sorted(history, key=lambda r: r.get("captured_at", ""))
    first, last = runs[0], runs[-1]
    incidents = sum(r.get("takeovers", 0) + r.get("secrets", 0) for r in runs)
    return {
        "runs": len(runs),
        "first_run": first.get("captured_at"),
        "last_run": last.get("captured_at"),
        "assets_first": first.get("assets", 0),
        "assets_last": last.get("assets", 0),
        "assets_growth": last.get("assets", 0) - first.get("assets", 0),
        "total_incidents": incidents,
        "incident_runs": sum(
            1 for r in runs if r.get("takeovers", 0) or r.get("secrets", 0)),
        "by_week": _by_week(runs),
    }


def _by_week(runs):
    weeks = {}
    for r in runs:
        ts = r.get("captured_at", "")
        try:
            d = dt.date.fromisoformat(ts[:10])
            wk = (d - dt.timedelta(days=d.weekday())).isoformat()
        except ValueError:
            continue
        slot = weeks.setdefault(wk, {"runs": 0, "assets": 0, "incidents": 0})
        slot["runs"] += 1
        slot["assets"] = max(slot["assets"], r.get("assets", 0))
        slot["incidents"] += r.get("takeovers", 0) + r.get("secrets", 0)
    return {k: weeks[k] for k in sorted(weeks)}


def render_markdown(summary):
    """Render the summary as a markdown trend report."""
    if summary.get("runs", 0) == 0:
        return "# Perimeter trend report\n\nNo runs recorded yet.\n"
    lines = [
        "# Perimeter trend report",
        "",
        f"- Runs recorded: **{summary['runs']}**"
        f" ({summary['first_run']} → {summary['last_run']})",
        f"- Assets watched: **{summary['assets_last']}**"
        f" (started at {summary['assets_first']},"
        f" growth {summary['assets_growth']:+d})",
        f"- Exposure incidents: **{summary['total_incidents']}**"
        f" across {summary['incident_runs']} run(s)",
        "",
        "| Week (Mon) | Runs | Assets | Incidents |",
        "|---|---|---|---|",
    ]
    for wk, slot in summary.get("by_week", {}).items():
        lines.append(f"| {wk} | {slot['runs']} | {slot['assets']} | {slot['incidents']} |")
    return "\n".join(lines) + "\n"

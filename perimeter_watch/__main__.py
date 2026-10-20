"""CLI: python -m perimeter_watch --watchlist watchlist.json --state state.json"""
import argparse
import datetime as dt
import json
import sys

from .enum_sources import ct_subdomains
from .resolver import resolve_all
from .state import load_state, save_state, diff
from .takeover import classify_all


def run(watchlist, state_path, enum_fn=None, resolve_fn=None, quiet=False):
    """One monitoring run. Returns (report, risks) and persists state."""
    enum_fn = enum_fn or ct_subdomains
    resolve_fn = resolve_fn or (lambda names: resolve_all(names))

    previous = load_state(state_path)
    current = {}
    errors = {}
    for domain in watchlist["domains"]:
        try:
            names = enum_fn(domain)
        except RuntimeError as error:
            errors[domain] = str(error)
            continue
        current[domain] = {name: None for name in names}
        resolved = resolve_fn(names)
        current[domain].update(resolved)

    report = diff(previous, current)
    risks = {d: classify_all({n: r for n, r in records.items()})
             for d, records in current.items()}

    snapshot = {
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "domains": current,
    }
    save_state(snapshot, state_path)
    return report, risks, errors


def main(argv=None):
    parser = argparse.ArgumentParser(prog="perimeter_watch",
                                     description="Continuous exposure monitoring for your domains")
    parser.add_argument("--watchlist", default="watchlist.json",
                        help="JSON file with a 'domains' list")
    parser.add_argument("--state", default="perimeter-state.json",
                        help="state file for diffing between runs")
    args = parser.parse_args(argv)

    with open(args.watchlist, encoding="utf-8") as fh:
        watchlist = json.load(fh)

    report, risks, errors = run(watchlist, args.state)

    for domain, changes in report.items():
        print(f"\n== {domain} — {changes['total']} known subdomains ==")
        if changes["added"]:
            print(f"  + {len(changes['added'])} new: {', '.join(changes['added'][:8])}")
        if changes["removed"]:
            print(f"  - {len(changes['removed'])} gone: {', '.join(changes['removed'][:8])}")
        if changes["changed"]:
            print(f"  ~ changed: {', '.join(changes['changed'][:8])}")
        if not any([changes["added"], changes["removed"], changes["changed"]]):
            print("  no changes")
    for domain, err in errors.items():
        print(f"\n!! {domain}: {err}", file=sys.stderr)

    takeover_found = False
    for domain, domain_risks in risks.items():
        for name, risk in domain_risks.items():
            takeover_found = True
            print(f"\nTAKEOVER RISK: {domain} :: {name} — {risk['evidence']}",
                  file=sys.stderr)

    return 2 if takeover_found else (1 if errors else 0)


if __name__ == "__main__":
    sys.exit(main())

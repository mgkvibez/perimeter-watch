"""CLI: python -m perimeter_watch --watchlist watchlist.json --state state.json"""
import argparse
import datetime as dt
import json
from pathlib import Path
import sys

from .alerts import build_alert, build_digest_alert, should_alert, dispatch, get_digest_config
from .enum_sources import ct_subdomains
from .resolver import resolve_all
from .scheduling import parse_watchlist_domains, evaluate_due_domains
from .state import load_state, load_last_scanned, save_state, diff
from .takeover import classify_all

RULESET_VERSION = "v0.4.0"


def run(watchlist, state_path, enum_fn=None, resolve_fn=None, fetch_fn=None,
        scan_due_only=False, digest=False, digest_threshold=None, now_fn=None, senders=None):
    """One monitoring run. Returns (report, risks, errors, secrets, buckets, dispatch) and persists state."""
    enum_fn = enum_fn or ct_subdomains
    resolve_fn = resolve_fn or (lambda names: resolve_all(names))

    from .secrets import scan_all
    from .buckets import scan_buckets
    from .trends import append_history

    if now_fn is None:
        now = dt.datetime.now(dt.timezone.utc)
    elif callable(now_fn):
        now = now_fn()
    else:
        now = now_fn
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)

    previous = load_state(state_path)
    last_scanned = load_last_scanned(state_path)

    parsed_domains = parse_watchlist_domains(watchlist)
    domain_configs = {d["name"]: d for d in parsed_domains}

    evaluations = evaluate_due_domains(watchlist, last_scanned, now=now)
    due_map = {e["name"]: e["due"] for e in evaluations}

    if scan_due_only:
        domains_to_scan = [name for name in domain_configs if due_map.get(name, True)]
    else:
        domains_to_scan = list(domain_configs.keys())

    current = dict(previous)
    errors = {}
    last_scanned_updated = dict(last_scanned)

    for domain in domains_to_scan:
        try:
            names = enum_fn(domain)
        except RuntimeError as error:
            errors[domain] = str(error)
            continue
        resolved = resolve_fn(names)
        current[domain] = dict(resolved)
        last_scanned_updated[domain] = now.isoformat(timespec="seconds")

    report = diff(previous, current)

    risks = {
        d: classify_all({n: r for n, r in records.items()})
        for d, records in current.items()
        if d in domains_to_scan
    }

    secret_findings = {}
    for domain in domains_to_scan:
        records = current.get(domain, {})
        live_bases = sorted({
            f"https://{n}" for n, r in records.items() if r is not None
        })
        secret_findings[domain] = scan_all(live_bases, fetch_fn=fetch_fn) if live_bases else {}

    bucket_findings = {}
    for domain in domains_to_scan:
        records = current.get(domain, {})
        found = scan_buckets(records, fetch=fetch_fn)
        if found:
            bucket_findings[domain] = found

    alert_payloads = {}
    for domain in domains_to_scan:
        alert = build_alert(
            domain,
            findings=secret_findings.get(domain, {}),
            risks=risks.get(domain, {}),
            changes=report.get(domain, {}),
            buckets=bucket_findings.get(domain, []),
        )
        if should_alert(alert):
            alert_payloads[domain] = alert

    snapshot = {
        "captured_at": now.isoformat(timespec="seconds"),
        "domains": current,
        "last_scanned": last_scanned_updated,
    }
    save_state(snapshot, state_path)

    channels = watchlist.get("alerts", {})
    digest_enabled, threshold = get_digest_config(watchlist, cli_digest=digest, cli_threshold=digest_threshold)
    dispatch_results = {}

    if alert_payloads and channels:
        if digest_enabled and len(alert_payloads) >= threshold:
            watchlist_name = watchlist.get("name", "watchlist")
            digest_alert = build_digest_alert(alert_payloads, watchlist_name=watchlist_name)
            dispatch_results = {"digest": dispatch(digest_alert, channels, senders=senders)}
        else:
            for domain, alert in alert_payloads.items():
                dispatch_results[domain] = dispatch(alert, channels, senders=senders)

    history_entry = {
        "captured_at": snapshot["captured_at"],
        "assets": sum(len(r) for r in current.values()),
        "dangling": sum(1 for r in current.values() for x in r.values() if x is None),
        "takeovers": sum(
            1 for r in risks.values()
            for x in r.values() if x and x.get("risk") == "takeover"),
        "secrets": sum(len(f) for f in secret_findings.values()),
        "buckets": sum(len(b) for b in bucket_findings.values()),
    }
    if watchlist.get("history"):
        append_history(watchlist["history"], history_entry)

    return report, risks, errors, secret_findings, bucket_findings, dispatch_results


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="perimeter_watch",
        description="Continuous exposure monitoring for your domains",
    )
    parser.add_argument("--watchlist", default="watchlist.json",
                        help="JSON file with a 'domains' list")
    parser.add_argument("--state", default="perimeter-state.json",
                        help="state file for diffing between runs")
    parser.add_argument("--trends", metavar="MD_OUT",
                        help="render the historical trend report and exit (requires a watchlist 'history')")
    parser.add_argument("--due", action="store_true",
                        help="list which domains are due for scanning and why")
    parser.add_argument("--scan-due", action="store_true",
                        help="scan only due domains")
    parser.add_argument("--digest", action="store_true",
                        help="enable alert digest mode")
    parser.add_argument("--digest-threshold", type=int, default=None,
                        help="threshold number of alerts to trigger digest mode")

    args = parser.parse_args(argv)

    with open(args.watchlist, encoding="utf-8") as fh:
        watchlist = json.load(fh)

    if args.due:
        last_scanned = load_last_scanned(args.state)
        evaluations = evaluate_due_domains(watchlist, last_scanned)
        print(f"== Perimeter Watch — Domain Due Status ({RULESET_VERSION}) ==")
        for ev in evaluations:
            status_tag = "[DUE]" if ev["due"] else "[OK] "
            print(f"  {status_tag} {ev['name']} (interval: {ev['interval_days']:g}d) — {ev['reason']}")
        return 0

    if args.trends:
        from .trends import load_history, summarize, render_markdown
        history_path = watchlist.get("history", "history.jsonl")
        summary = summarize(load_history(history_path))
        Path(args.trends).write_text(render_markdown(summary), encoding="utf-8")
        return 0

    report, risks, errors, secret_findings, bucket_findings, dispatch_results = run(
        watchlist,
        args.state,
        scan_due_only=args.scan_due,
        digest=args.digest,
        digest_threshold=args.digest_threshold,
    )

    any_changes = False
    for domain, changes in report.items():
        print(f"\n== {domain} — {changes['total']} known subdomains ==")
        if changes["added"]:
            print(f"  + {len(changes['added'])} new: {', '.join(changes['added'][:8])}")
            any_changes = True
        if changes["removed"]:
            print(f"  - {len(changes['removed'])} gone: {', '.join(changes['removed'][:8])}")
            any_changes = True
        if changes["changed"]:
            print(f"  ~ changed: {', '.join(changes['changed'][:8])}")
            any_changes = True
        if not any([changes["added"], changes["removed"], changes["changed"]]):
            print("  no changes")

    for domain, err in errors.items():
        print(f"\n!! {domain}: {err}", file=sys.stderr)

    for domain, per_base in secret_findings.items():
        for base, findings in per_base.items():
            for f in findings:
                print(f"SECRET EXPOSURE: {domain} :: {f['url']} — {f['evidence']}",
                      file=sys.stderr)

    takeover_found = False
    for domain, domain_risks in risks.items():
        for name, risk in domain_risks.items():
            takeover_found = True
            print(f"\nTAKEOVER RISK: {domain} :: {name} — {risk['evidence']}",
                  file=sys.stderr)

    exposure_found = any(any(v) for per_base in secret_findings.values() for v in per_base.values())
    bucket_found = any(any(v) for v in bucket_findings.values())

    if not (takeover_found or exposure_found or bucket_found or errors or any_changes):
        print(f"\nno issues found by ruleset {RULESET_VERSION}")

    if takeover_found:
        return 2
    if exposure_found:
        return 3
    if bucket_found:
        return 4
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

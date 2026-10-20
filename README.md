# perimeter-watch

> Watch your perimeter while you sleep.

**Status: v0.1.0 — subdomain diffing + dangling CNAME takeover detection shipping.** Secret scanning and alert channels are next on the roadmap.

Continuous external exposure monitoring for security teams and bug bounty hunters:

- Feed it your domains; it runs on a schedule (cron or GitHub Actions)
- Detects NEW exposures: dangling CNAMEs, takeover-eligible services, exposed
  buckets, leaked-looking secrets on your scope
- Reports diffs, not noise — you only hear about what changed
- State is a plain JSON/SQLite file you own. No cloud, no account.

The free tier of GitHub Actions IS the product: point it at a config and get
perimeter alerts without paying for an attack-surface platform.

## Usage (planned)

    uvx perimeter-watch scan --config perimeter.yaml

## Quickstart

    python -m perimeter_watch --watchlist watchlist.json --state perimeter-state.json

First run: baselines every CT-log subdomain. Second run on: diffs added /
removed / changed records, flags names that stopped resolving, and exits 2 on
a takeover signature (dangling CNAME to a known-vulnerable service).

The GitHub Actions template in `templates/perimeter-watch.yml` makes the
free tier the product: one workflow file = free daily monitoring.

11 offline tests (enumeration and resolution are injected, no network):

    python -m unittest discover -s tests

## Documentation

- [docs/research.md](docs/research.md) — market research and competitive landscape
- [docs/roadmap.md](docs/roadmap.md) — development milestones toward v0.1.0

## License

MIT

# perimeter-watch

> Watch your perimeter while you sleep.

**Status: early development.** This repo is public research + planning until the first release.

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

## Documentation

- [docs/research.md](docs/research.md) — market research and competitive landscape
- [docs/roadmap.md](docs/roadmap.md) — development milestones toward v0.1.0

## License

MIT

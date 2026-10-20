# Changelog

## v0.1.0 — 2026-10-20

- Subdomain enumeration via certificate transparency (crt.sh)
- JSON-snapshot state + diff engine: added, removed, changed records;
  newly-dangling means previously-resolving names that stopped (a
  first-seen unresolvable name is not a regression)
- Dangling CNAME takeover detection with 12 known-vulnerable service
  signatures (Heroku, GitHub Pages, Azure, CloudFront, ...)
- CLI with CI-friendly exit codes (2 = takeover risk)
- GitHub Actions workflow template — the free tier is the product
- 11 offline tests; enumeration and resolution fully injectable

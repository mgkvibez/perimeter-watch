# ROADMAP — perimeter-watch

## v0.1.0 — MVP
- [x] Subdomain enumeration + diff engine (state in JSON/SQLite)
- [x] Dangling CNAME / takeover signature detection
- [x] GitHub Actions workflow template (the free tier IS the product)

## v0.2.0
- [x] Secret exposure scanning on scoped assets
- [x] Alert channels: CLI, email, webhook

## v0.3.0
- [x] Exposed bucket detection (S3 and friends)
- [x] Historical trend report

## v0.4.0
- [x] Multi-domain scan scheduling (`--due`, `--scan-due`, per-domain intervals)
- [x] Delta alert digests (`--digest`, `--digest-threshold N`)

## v1.0.0
- [ ] Stable config format, full docs, launch on r/bugbounty

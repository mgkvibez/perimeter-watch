# RESEARCH — perimeter-watch
Updated: 2026-10-16

## Market thesis
Continuous external attack-surface monitoring for small security teams and bug
bounty hunters. The existing tools in this niche are tiny or half-abandoned; the
biggest is 53 stars. Quality wins here by default.

## Competitive landscape (GitHub, Oct 2026)
| Repo | Stars | Gap we exploit |
|---|---|---|
| h0tak88r/subfalcon | 53 | Subdomain enumeration only, not continuous monitoring |
| melbadry9/ScanApi | 38 | API-only, no alerting/diff UX |
| strikergoutham/Anti-Takeover | 12 | Narrow: subdomain takeover only |
| everything else | <10 | Abandoned or one-off scripts |

## Positioning
"Watch your perimeter while you sleep." Feed it domains, it runs on a
schedule (cron/GitHub Actions), detects NEW exposures (dangling CNAMEs,
takeover-eligible services, exposed buckets, leaked-looking secrets on your
program's scope), and reports diffs, not noise. State is a plain JSON/SQLite
file you own.

## Launch playbook
- uvx perimeter-watch scan --config perimeter.yaml
- Ships with a GitHub Actions workflow so the free tier IS the product
- Demo GIF: notification of a newly dangling CNAME before anyone exploits it
- Launch: r/bugbounty, r/netsec, InfoSec Twitter/X
- v0.1.0 release: subdomain takeover + diff engine; v0.2: secrets scanning

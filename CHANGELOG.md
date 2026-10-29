# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-29

### Added

- Local-network discovery, port/service profiling, CPE-based NVD correlation, and explicit allowlisted CVE verification.
- Authenticated public hostname inventory with DNS, TLS, HTTP redirect, security-header, cookie, SPF, DMARC, and CDN provider findings.
- Cloudflare, CloudFront, Fastly, Akamai, Azure Front Door, Vercel, and Netlify detection.
- Explicit known-origin reachability checks for up to four supplied IPs, compared against the last edge scan, without persisting addresses.
- Read-only Cloudflare API checks for proxied DNS, SSL mode, HTTPS redirect, minimum TLS, TLS 1.3, DNSSEC, and managed WAF visibility.
- CSV and JSON report downloads.
- Notifications on job failures, new high/medium findings, new high CVEs, and confirmed vulnerabilities.
- `scripts/install.sh` one-command installer with `--uninstall`, `--backup`, `--keep-data`, and `--purge`.
- Hardware detection with `minimal`/`balanced`/`fast` profiles controlling worker count, Nmap timing, and default port range.
- CIRCL Vulnerability-Lookup as a second CVE source, with local version-range matching and a `product` confidence label for unverifiable matches.
- CISA KEV and FIRST EPSS enrichment, refreshed on demand with `flask --app cvescout refresh-intel` and used to rank the report.
- `CVESCOUT_CVE_SOURCES` to choose which CVE sources are queried.
- System page: version, schema version, hardware profile, database size, row counts, sources, last job per kind.
- Pagination for reports and the audit log, plus a log level filter; exports stay complete.
- Auto-refresh on device and domain pages while scans run, preserving scroll position.
- Favicon, 10-minute static asset caching, column-scoped table headers, and a print stylesheet.
- `cvescout/views.py` split into `cvescout/views/` (devices, domains, reports, settings, system)
  with an unchanged route table.
- SARIF 2.1.0 export (`/reports.sarif`) with stable per-target fingerprints.
- Per-device CSV and JSON exports, and risk columns (match, source, KEV, EPSS) in every export.
- Finding lifecycle: `first_seen` and `resolved_at` on CVE and public-hostname findings (migration v4),
  a **New** badge, and a resolved count on the dashboard. Resolved findings are hidden from current
  reports but keep their history; a returning finding reopens and alerts again.
- Systemd units ship inside the package and render with `flask --app cvescout install-units`.
- Settings page for webhook, ntfy, gotify, and email JSON API channels, with masked secrets and a test button.
- Synchronous `flask --app cvescout scan --kind ...` command with a bundled systemd service and timer for unattended scans.
- Versioned SQLite migrations (`PRAGMA user_version`) so schema changes can ship safely.
- Expiring sessions via `CVESCOUT_SESSION_HOURS` (default 12 hours).
- History retention via `CVESCOUT_HISTORY_DAYS` (default 90 days) and `flask --app cvescout prune-history`.
- Audit log covering scans, checks, provider checks, and login activity.
- GitHub Actions CI across Python 3.11–3.13, CodeQL, Dependabot, issue forms, and a tagged release workflow.

### Fixed

- Vulnerability checks left `running` by a restart are now marked failed.
- Origin reachability failures no longer persist supplied origin IPs in check results, jobs, or audit events.
- A failed domain scan no longer updates `last_scanned`, so stale findings are not presented as current.
- Repeated failed logins are throttled and logged once when the limit is crossed.
- Identical queued or running scans, checks, and provider checks are refused instead of duplicated.
- Responses include CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, and conditional HSTS headers.

### Security

- Public scans reject any non-global resolved address and connect to the validated IP with the hostname as TLS SNI and HTTP `Host`, blocking internal SSRF and DNS rebinding.
- Cloudflare tokens are read from the environment, sent only to `api.cloudflare.com`, and never stored or logged.
- Cookie values observed during public scans are analyzed in memory but never persisted.

## [0.1.0]

- Internal preview: local inventory and CVE correlation only. Superseded by 0.2.0; not published.

[0.2.0]: https://github.com/Dylpickle-Studios/cvescout/releases/tag/v0.2.0
[0.1.0]: https://github.com/Dylpickle-Studios/cvescout/compare/v0.1.0...v0.2.0

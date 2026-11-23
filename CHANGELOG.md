# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- CVE verification now covers more than the four 2014 SSL bugs: the MS17-010 (EternalBlue) family and MS12-020 RDP detectors joined the allowlist after verifying they are non-destructive, and every check reports clearly when the local Nmap build lacks the detector.
- Payload-free **version re-verification** for any version-based CVE match: re-probes the single port's service version, re-correlates against the CVE sources, and reports `version_confirmed` or `version_not_reproduced`. Most findings that previously said "no safe checker" now have a safe, meaningful check.
- Passive **CVE correlation for public hostnames**: software disclosed in Server/X-Powered-By headers is mapped to CPEs through an explicit product table (nginx, Apache, IIS, openresty, lighttpd, PHP) and correlated with the same cached NVD/CIRCL sources as local ports. Findings use the existing lifecycle, reports, and alert policy; product-only leads never alert.
- New domain edge findings: weak/legacy TLS cipher suites, classified TLS failures (hostname mismatch, expired dates, untrusted chain), expired-certificate wording, X-Powered-By version disclosure, cookie SameSite, HTTP redirects to a different hostname, SPF DNS-lookup limit (>10), positive CAA/DNSSEC signals, and RFC 9116 security.txt presence (one extra bounded GET, text analyzed in memory and never stored).
- Cloudflare checks add security level and browser integrity check.
- Device pages show what each check does, offer the right check kind per finding, and render human-readable check results.
- **Finding acknowledgment** (migration v6): acknowledge any CVE or domain finding with a reason to hide it from current reports, dashboards, and alerts. The decision is audited, persists across rescans (so backported-fix false positives stay silenced), is reversible, and can be included in reports and exports with `?acknowledged=1`.
- **Explicit product -> CPE map for local ports** (`cvescout/product_cpes.py`): when Nmap reports a product and version but no CPE, common services (OpenSSH, MySQL/MariaDB, PostgreSQL, Redis, Samba, ProFTPD, Tomcat, Jetty, Node.js, OpenSSL, Mosquitto, Plex, RouterOS, OpenWrt, and more) are still correlated. Unknown products are skipped, never guessed; vendor-churn products list every candidate CPE.
- **CMS detection for public hostnames**: WordPress, Drupal, and Joomla versions from meta generator tags and X-Generator headers feed the same passive CVE correlation. Page content is parsed in memory; only the product/version string is kept.
- CIRCL version matching understands OpenSSL-style letter releases (1.1.1k sorts after 1.1.1 and before 1.1.1l).
- `flask --app cvescout scan --kind all` runs the full pipeline (network → devices → ports → vulnerabilities → domains) in order, keeps going past a failed stage, and exits non-zero if any stage failed — a complete nightly timer target.
- `flask --app cvescout backup --dest DIR` copies the database with SQLite's online backup API (safe while running, WAL-aware) plus the session secret, with restrictive modes on new directories and files.
- CI runs a real-Nmap smoke test against loopback (the scanner tests otherwise use hand-written XML fixtures) and enforces a 75% coverage floor.
- Opt-in **UDP scanning**: `CVESCOUT_UDP_PORTS` adds a UDP port expression to the combined port scan (`-sU -p T:…,U:…`); verification checks and version re-probes target the right protocol. Off by default because unprivileged UDP is slow.
- **Monitoring endpoints**: open `/healthz` liveness probe and Prometheus-text `/metrics` (inventory, findings by state/severity, KEV size, last successful job per kind, build info), disabled unless `CVESCOUT_METRICS_TOKEN` is set and then bearer-token gated.
- Dashboard **30-day findings trend**: server-rendered SVG of daily new vs resolved CVE findings, no JavaScript.
- CI type-checks the package with mypy (`check_untyped_defs` enabled).

### Changed

- Check result parsing prefers the structured `State:` lines NSE vuln scripts emit, with the old substring heuristic as fallback.
- Scripts that execute code on the target (`http-vuln-cve2012-1823`) or can crash it (`smb-vuln-ms08-067`) are documented as deliberately excluded from the allowlist.
- SQLite WAL mode now uses `synchronous=NORMAL`, the documented-safe pairing: faster commits and less SD card wear on the Pi Zero.
- History retention also prunes stale CVE source cache payloads.
- The installer downloads release packages into a private `mktemp` directory instead of a predictable `/tmp` path, and keeps installed code root-owned (only `instance/` belongs to the service account).
- `cvescout-scan.service` ships the same hardening as the main unit (`ProtectSystem=strict`, `PrivateTmp`, `ProtectHome`, `NoNewPrivileges`).
- CI matrix adds Python 3.14.
- Operations guide documents the unprivileged-Nmap discovery fallback and an optional `CAP_NET_RAW` drop-in for full ARP discovery.

### Fixed

- KEV refresh no longer deletes EPSS scores: `flask refresh-intel` wiped the EPSS value of every KEV CVE because the catalogue refresh deleted and re-inserted rows. The flag is now cleared with an UPDATE instead.
- A CVE source outage no longer marks all findings resolved: when every enabled source fails for a port and nothing is cached, stored findings are kept instead of being treated as vanished.
- A public-hostname finding that disappears and returns now alerts again, matching the CVE lifecycle and the documented behavior.
- CIRCL version entries with only `lessThan`/`lessThanOrEqual` (no lower version) now produce `version` matches instead of being downgraded to `product` leads; upper bounds are exclusive/inclusive per the CVE 5.x schema.
- NVD lookups follow `startIndex` pagination instead of silently truncating at 2000 results per CPE.
- NVD rate-limit pacing now also applies after failed requests, so a run of 403/429 responses cannot become a retry burst.
- Public hostname probes enforce a total time budget (connect, TLS, headers, and body), so a trickle-feeding server cannot hold the single scan worker indefinitely.
- The duplicate-job guard is atomic: a partial unique index on active jobs (migration v5) closes the check-then-insert race, and the CLI reports a busy target cleanly.
- Concurrent first starts no longer crash on the secret-key file race; the losing process reads the winner's key.
- Cookie findings are keyed by cookie name instead of position, so reordered `Set-Cookie` headers no longer resolve and reopen the same findings.
- Dashboard device CVE counts exclude resolved findings, consistent with device pages and reports.
- The domain detail page auto-refreshes while a domain scan is queued or running, not only during provider checks.

### Security

- The post-login `next` redirect rejects backslashes and control characters, closing a browser-normalization open-redirect bypass (`/\host`).
- Login with an unknown username now verifies against a dummy hash, so response timing no longer reveals which usernames exist.
- Application responses carry `Cache-Control: no-store` so findings and audit data do not linger in browser or proxy caches; static assets keep their own max-age.
- Releases publish `SHA256SUMS`, and the installer verifies the downloaded package's checksum before installing (with a warning for older releases that predate checksums).

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

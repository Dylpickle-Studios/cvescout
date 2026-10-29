# Architecture

## Components

- `cvescout/scanner.py` — target validation, Nmap execution, XML parsing, device and port inventory
- `cvescout/cve.py` — CPE normalization, source merging, correlation, alert selection
- `cvescout/circl.py` — CIRCL Vulnerability-Lookup source with local version-range matching
- `cvescout/exploit_intel.py` — CISA KEV and FIRST EPSS refresh plus local cache
- `cvescout/checks.py` — explicit allowlist of bounded Nmap NSE verification scripts
- `cvescout/domain_scanner.py` — public-hostname validation, DNS records, and direct-IP TLS/HTTP probes
- `cvescout/domain_findings.py` — edge/provider detection and normalized external findings
- `cvescout/platform.py` — hardware detection and scan profiles (workers, Nmap timing, default ports)
- `cvescout/provider_checks.py` — explicit known-origin reachability and edge comparison without IP persistence
- `cvescout/cloudflare_checks.py` — fixed-endpoint, read-only Cloudflare configuration checks
- `cvescout/jobs.py` — one in-process worker, job state, check state, audit events
- `cvescout/db.py` — SQLite schema and connection lifecycle
- `cvescout/auth.py` — login, password verification, CSRF protection
- `cvescout/views/` — server-rendered UI routes, one module per area (devices, domains, reports,
  settings, system) sharing the `main` blueprint so endpoint names stay stable

## Data flow

```text
user click -> queued job -> single worker -> nmap/NVD ----------------> SQLite -> HTML report
                                      \-> DNS/TLS/HTTP edge -----------/        -> audit event
                                      \-> known origin / Cloudflare API /
```

Network and port scanning use Nmap XML output. No shell is involved; subprocess arguments are passed as a list. Every target is parsed as an IPv4 address and checked against configured authorized CIDRs before Nmap runs.

Nmap service detection supplies CPE identifiers. CVE Scout converts legacy CPE 2.2 strings to CPE 2.3, queries each enabled source, and keeps the strongest claim per CVE: an exact match wins over a product match. NVD answers only for CPEs it enriched; CIRCL answers for the CPE vendor and product, so its results are classified locally as `version` when a declared version range covers the discovered version, otherwise `product`. Product-only matches are stored but never trigger notifications. Missing CPE means no automatic CVE match; product-name guessing is intentionally avoided because false positives are high.

Public domain scans normalize an exact hostname, resolve all A/AAAA addresses, and reject the scan if any address is not globally routable. Connections then use a validated IP directly while retaining the hostname for TLS SNI and HTTP `Host`, preventing a second DNS lookup from rebinding to an internal address. Scans query DNS metadata and make one bounded root request on ports 80 and 443. Redirects are not followed.

Known-origin checks accept one user-supplied globally routable IP, use it only as an in-memory job argument, and store only protocol/status/fingerprint comparisons. Cloudflare checks use a fixed API base URL plus an environment-only bearer token; results contain zone name and control states but never the token.

## Concurrency

One `ThreadPoolExecutor` is created per process and sized by the hardware profile (`cvescout/platform.py`): 1 worker on a Pi Zero, up to 4 on a machine with 4+ cores and 4 GB RAM. Workers run different jobs in parallel; the duplicate-job guard still prevents two scans of the same target. SQLite runs in WAL mode and each worker opens its own connection, and the NVD rate limiter is process-global, so parallel scans do not trip NVD limits.

Run one application process. Multiple Gunicorn workers would each create their own queue and executor, so leave `--workers 1` and scale with threads instead.

Jobs are recorded before execution. On startup, abandoned queued/running jobs become failed. Queue contents themselves are not recovered after process restart.

## Trust boundaries

- Browser input: CSRF checked, integer IDs parsed, no user-supplied command fragments.
- Local scan targets: constrained to configured CIDRs.
- Public hostnames: strict hostname syntax, all addresses must be public, direct validated-IP connections, ports 80/443 only.
- HTTP responses: bodies capped by `CVESCOUT_DOMAIN_MAX_BYTES`; cookie values are analyzed in memory but not stored.
- Known origins: public IP only, explicit authorization checkbox, never persisted or logged, ports 80/443 only.
- Cloudflare: fixed `api.cloudflare.com` endpoint by default, environment-only token, read operations only.
- NVD: remote JSON treated as data and escaped by Jinja.
- Active checks: CVE-to-script mapping is hard-coded; users cannot choose arbitrary NSE scripts or arguments.
- Database: parameterized SQL except placeholder count generated from internal CVE IDs.
- Findings are never deleted by a scan: a disappeared finding gets `resolved_at`, and a returning one clears it. Queries that show "current" findings filter on `resolved_at IS NULL`.

## Known limits

- Local network inventory is IPv4 only.
- Local service inventory scans TCP only.
- Public scans assess one exact hostname and its current edge; no subdomain discovery, historical DNS, origin enumeration, or exploit checks.
- Origin reachability checks test only one supplied IP at one moment and cannot prove all possible origin paths are closed.
- Cloudflare checks cover selected zone controls, not every product, account policy, firewall rule, Worker, or application vulnerability.
- Header/email findings are configuration signals and can require application-specific review.
- Exact CPE correlation depends on Nmap service fingerprint quality.
- Worker parallelism is bounded by the local profile; there is no queue persistence across restarts.
- CIRCL matches on vendor and product, so it can surface CVEs that do not apply to the installed version. They are labelled `product` and excluded from alerts.
- KEV and EPSS are cached locally; when the network is unavailable, ranking falls back to CVSS and nothing fails.
- Current report is live state, not immutable snapshots.

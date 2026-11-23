# Architecture

## Components

- `cvescout/scanner.py` — target validation, Nmap execution, XML parsing, device and port inventory
- `cvescout/cve.py` — CPE normalization, source merging, correlation, alert selection
- `cvescout/product_cpes.py` — explicit nmap product -> CPE map for fingerprints without a CPE
- `cvescout/circl.py` — CIRCL Vulnerability-Lookup source with local version-range matching
- `cvescout/exploit_intel.py` — CISA KEV and FIRST EPSS refresh plus local cache
- `cvescout/checks.py` — explicit verification: allowlisted non-destructive NSE detectors plus payload-free version re-verification
- `cvescout/domain_scanner.py` — public-hostname validation, DNS records, and direct-IP TLS/HTTP probes
- `cvescout/domain_findings.py` — edge/provider detection and normalized external findings
- `cvescout/domain_cves.py` — passive CVE correlation for public hostnames from disclosed header versions
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

Nmap service detection supplies CPE identifiers. CVE Scout converts legacy CPE 2.2 strings to CPE 2.3, queries each enabled source, and keeps the strongest claim per CVE: an exact match wins over a product match. When a port has a product and version but no CPE, an explicit product map supplies candidate CPEs; unknown products are skipped rather than guessed. NVD answers only for CPEs it enriched; CIRCL answers for the CPE vendor and product, so its results are classified locally as `version` when a declared version range covers the discovered version, otherwise `product`. Product-only matches are stored but never trigger notifications. Missing CPE and an unmapped product means no automatic CVE match; product-name guessing is intentionally avoided because false positives are high.

Public domain scans normalize an exact hostname, resolve all A/AAAA addresses, and reject the scan if any address is not globally routable. Connections then use a validated IP directly while retaining the hostname for TLS SNI and HTTP `Host`, preventing a second DNS lookup from rebinding to an internal address. Scans query DNS metadata and make bounded root and `/.well-known/security.txt` requests on ports 80 and 443. Redirects are not followed. Software versions disclosed in response headers are mapped to CPEs through an explicit product table and correlated with the cached CVE sources; the results are stored as ordinary domain findings with the same lifecycle and alert policy.

Known-origin checks accept one user-supplied globally routable IP, use it only as an in-memory job argument, and store only protocol/status/fingerprint comparisons. Cloudflare checks use a fixed API base URL plus an environment-only bearer token; results contain zone name and control states but never the token.

## Concurrency

One `ThreadPoolExecutor` is created per process and sized by the hardware profile (`cvescout/platform.py`): 1 worker on a Pi Zero, up to 4 on a machine with 4+ cores and 4 GB RAM. Workers run different jobs in parallel; the duplicate-job guard still prevents two scans of the same target. SQLite runs in WAL mode and each worker opens its own connection, and the NVD rate limiter is process-global, so parallel scans do not trip NVD limits.

Run one application process. Multiple Gunicorn workers would each create their own queue and executor, so leave `--workers 1` and scale with threads instead.

Jobs are recorded before execution. On startup, abandoned queued/running jobs become failed. Queue contents themselves are not recovered after process restart.

## Trust boundaries

- Browser input: CSRF checked, integer IDs parsed, no user-supplied command fragments.
- Local scan targets: constrained to configured CIDRs.
- Public hostnames: strict hostname syntax, all addresses must be public, direct validated-IP connections, ports 80/443 only.
- HTTP responses: bodies capped by `CVESCOUT_DOMAIN_MAX_BYTES`; cookie values and security.txt text are analyzed in memory but not stored. Meta generator tags are parsed in memory; only the resulting product/version string is kept, never page content.
- Known origins: public IP only, explicit authorization checkbox, never persisted or logged, ports 80/443 only.
- Cloudflare: fixed `api.cloudflare.com` endpoint by default, environment-only token, read operations only.
- NVD: remote JSON treated as data and escaped by Jinja.
- Active checks: CVE-to-script mapping is hard-coded; users cannot choose arbitrary NSE scripts or arguments. Allowlisted detectors never execute code on the target or change its state; scripts that do are excluded. The version re-verification check is a service probe plus cached source lookups and sends no payloads.
- Domain CVE correlation: only header-derived CPEs from an explicit product table leave the network; no product-name guessing, no body parsing, no extra requests beyond the bounded probes.
- Database: parameterized SQL except placeholder count generated from internal CVE IDs.
- Monitoring: `/healthz` is open and reveals only liveness; `/metrics` is disabled unless `CVESCOUT_METRICS_TOKEN` is set, and then requires a matching bearer token compared in constant time.
- Findings are never deleted by a scan: a disappeared finding gets `resolved_at`, and a returning one clears it. Queries that show "current" findings filter on `resolved_at IS NULL`.
- Acknowledgment is a standing, audited decision: an acknowledged finding is hidden from current reports and alerts but keeps matching across rescans (backported fixes stay silenced). It persists until manually removed; reports and exports can include it with `?acknowledged=1`.

## Known limits

- Local network inventory is IPv4 only.
- Local service inventory scans TCP by default; UDP is opt-in via `CVESCOUT_UDP_PORTS` and slower unprivileged.
- Public scans assess one exact hostname and its current edge; no subdomain discovery, historical DNS, origin enumeration, or exploit checks.
- Origin reachability checks test only one supplied IP at one moment and cannot prove all possible origin paths are closed.
- Cloudflare checks cover selected zone controls, not every product, account policy, firewall rule, Worker, or application vulnerability.
- Header/email findings are configuration signals and can require application-specific review.
- Exact CPE correlation depends on Nmap service fingerprint quality.
- Domain CVE correlation depends on disclosed header versions, which can be masked or backported; matches are leads, and a version confirmation is not proof of exploitability.
- Worker parallelism is bounded by the local profile; there is no queue persistence across restarts.
- CIRCL matches on vendor and product, so it can surface CVEs that do not apply to the installed version. They are labelled `product` and excluded from alerts.
- KEV and EPSS are cached locally; when the network is unavailable, ranking falls back to CVSS and nothing fails.
- Current report is live state, not immutable snapshots.

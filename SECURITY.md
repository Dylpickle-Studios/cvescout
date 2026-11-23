# Security policy

## Supported versions

Latest release receives security fixes.

## Reporting

Do not open public issues for exploitable security defects. Use repository security advisory feature or contact maintainer privately. Include affected version, reproduction, impact, and suggested mitigation. Do not include real network inventory or credentials.

## Deployment warnings

- Use only on networks, devices, and public hostnames you are authorized to scan.
- Do not expose web UI directly to internet.
- Use HTTPS and set `CVESCOUT_HTTPS=1` when access crosses a network.
- Restrict configured CIDRs and OS firewall access.
- Protect `instance/`, database backups, public-domain findings, NVD/Cloudflare API keys, and reverse-proxy credentials.
- Run as unprivileged dedicated user. Current scans do not require root.

## Active verification policy

Verification never runs during inventory or CVE correlation. User must click **Check** for one finding. Two check kinds exist: hard-coded, bounded Nmap NSE scripts assessed as non-destructive (no code execution on the target, no state change, no crash risk), and a payload-free version re-verification that re-probes one port's service version and re-correlates it against the CVE sources. Arbitrary scripts, script arguments, exploit payloads, credential attacks, and denial-of-service checks are out of scope. A version confirmation is not proof of exploitability.

## Hardening in the app

- Failed logins from the same address and username are throttled after 5 attempts for 15 minutes. State is per process, so restarting clears it and running multiple workers would weaken it.
- Responses carry a restrictive Content-Security-Policy, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: same-origin`. HSTS is sent only when `CVESCOUT_HTTPS=1`.
- Duplicate scans, vulnerability checks, and provider checks are refused while identical work is queued or running; a partial unique index makes the guard atomic.
- A failed or restart-interrupted check is recorded as failed; a failed domain scan keeps its previous `last_scanned` time so old findings never look fresh.
- Application responses carry `Cache-Control: no-store` so findings and audit data do not linger in caches; static assets keep their own max-age.
- Login with an unknown username verifies against a dummy hash, so response timing cannot enumerate valid usernames.

## Installer trust

`install.sh` runs as root and needs `apt`, `systemctl`, and a service account. Download and read it before running; the project never asks you to pipe a remote script into a shell. Create the release asset from the same tagged commit you audit. Releases publish `SHA256SUMS`; the installer downloads into a private `mktemp` directory and verifies the package checksum before installing. Installed code stays root-owned; only `instance/` belongs to the service account. Uninstall writes a database and secret backup by default, and `--purge` is the only path that deletes data.

## Notification credentials

Notification channel URLs and tokens are administered only by an authenticated user and stored in the local SQLite database. Tokens are never rendered back to the browser and are redacted from error messages and audit events. Because LAN-hosted ntfy and gotify are normal targets, channel URLs are allowed to point at private addresses; the settings page is therefore an administrator-equivalent control. Protect database backups accordingly.

## Public hostname scan policy

Public scans require an authenticated user to confirm authorization when adding a hostname. Scanner accepts only a hostname, resolves it before connecting, rejects any non-global address, and connects directly to the validated public IP with hostname-based TLS SNI and HTTP `Host`. It contacts only ports 80 and 443, requests only `/` and `/.well-known/security.txt`, caps response bytes and total probe time, does not follow redirects, and does not store cookie values or page content. Software versions disclosed in headers or meta generator tags are mapped to CPEs through an explicit product table and correlated with the cached CVE sources; only the CPE leaves the network, and header versions may be masked or backported.

Subdomain enumeration, historical DNS searches, automated origin discovery, credential submission, exploit payloads, and denial-of-service testing are out of scope. Cloudflare or other provider detection means the public edge was observed; it does not prove a hidden origin cannot be reached another way.

Known-origin verification is an explicit user action. It accepts up to four already-known globally routable IPs, contacts only ports 80 and 443 with the configured hostname, requires a prior domain scan, and never stores or logs the addresses. A negative result covers only the supplied addresses and is not proof that every origin path is protected.

Cloudflare verification uses an optional environment-only bearer token and fixed Cloudflare API endpoint. Use least-privilege read permissions. Token values are never stored, rendered, or logged.

## Monitoring endpoints

`/healthz` is unauthenticated and returns only liveness. `/metrics` is disabled unless `CVESCOUT_METRICS_TOKEN` is set and then requires a matching bearer token; it exposes aggregate counts (inventory, findings by state and severity, KEV size, job timestamps, build info), never finding details, device addresses, or credentials.

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

Verification never runs during inventory or CVE correlation. User must click **Check** for one finding. Only hard-coded, bounded Nmap NSE scripts assessed as non-destructive are accepted. Arbitrary scripts, script arguments, exploit payloads, credential attacks, and denial-of-service checks are out of scope.

## Hardening in the app

- Failed logins from the same address and username are throttled after 5 attempts for 15 minutes. State is per process, so restarting clears it and running multiple workers would weaken it.
- Responses carry a restrictive Content-Security-Policy, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: same-origin`. HSTS is sent only when `CVESCOUT_HTTPS=1`.
- Duplicate scans, vulnerability checks, and provider checks are refused while identical work is queued or running.
- A failed or restart-interrupted check is recorded as failed; a failed domain scan keeps its previous `last_scanned` time so old findings never look fresh.

## Installer trust

`install.sh` runs as root and needs `apt`, `systemctl`, and a service account. Download and read it before running; the project never asks you to pipe a remote script into a shell. Create the release asset from the same tagged commit you audit. Uninstall writes a database and secret backup by default, and `--purge` is the only path that deletes data.

## Notification credentials

Notification channel URLs and tokens are administered only by an authenticated user and stored in the local SQLite database. Tokens are never rendered back to the browser and are redacted from error messages and audit events. Because LAN-hosted ntfy and gotify are normal targets, channel URLs are allowed to point at private addresses; the settings page is therefore an administrator-equivalent control. Protect database backups accordingly.

## Public hostname scan policy

Public scans require an authenticated user to confirm authorization when adding a hostname. Scanner accepts only a hostname, resolves it before connecting, rejects any non-global address, and connects directly to the validated public IP with hostname-based TLS SNI and HTTP `Host`. It contacts only ports 80 and 443, requests only `/`, caps response bytes, does not follow redirects, and does not store cookie values.

Subdomain enumeration, historical DNS searches, automated origin discovery, credential submission, exploit payloads, and denial-of-service testing are out of scope. Cloudflare or other provider detection means the public edge was observed; it does not prove a hidden origin cannot be reached another way.

Known-origin verification is an explicit user action. It accepts up to four already-known globally routable IPs, contacts only ports 80 and 443 with the configured hostname, requires a prior domain scan, and never stores or logs the addresses. A negative result covers only the supplied addresses and is not proof that every origin path is protected.

Cloudflare verification uses an optional environment-only bearer token and fixed Cloudflare API endpoint. Use least-privilege read permissions. Token values are never stored, rendered, or logged.

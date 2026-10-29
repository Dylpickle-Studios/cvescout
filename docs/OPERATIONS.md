# Operations

## Install

Use the installer unless you have a reason not to:

```sh
curl -fsSLO https://github.com/Dylpickle-Studios/cvescout/releases/latest/download/install.sh
less install.sh
sudo bash install.sh --network 192.168.1.0/24 --with-timer
```

It installs into `/opt/cvescout`, creates the `cvescout` account, writes `/etc/cvescout.env`, renders the systemd units for that prefix, and prompts for an administrator password. Re-running upgrades the code and keeps `instance/`.

Uninstall, with the data choices spelled out:

```sh
sudo bash install.sh --uninstall              # backup to /var/backups/cvescout-<timestamp>, then remove
sudo bash install.sh --uninstall --backup /mnt/usb   # backup to a specific directory
sudo bash install.sh --uninstall --keep-data  # keep instance/, remove the code
sudo bash install.sh --uninstall --purge      # remove everything, no backup
```

Unit files are shipped inside the package, so a manual install can render them too:

```sh
flask --app cvescout install-units --target /etc/systemd/system --prefix /opt/cvescout --user cvescout
```

## Recommended deployment

Keep CVE Scout on a trusted management network. Bind to localhost and place an HTTPS reverse proxy in front, or bind to Pi LAN address with firewall rules limiting access to administrator devices.

Do not expose it to internet. Auth is intended as a management control, not internet-edge hardening.

## systemd

Copy repository to `/opt/cvescout`, create virtual environment, install package, then create `/etc/cvescout.env`:

```ini
CVESCOUT_NETWORKS=192.168.1.0/24
CVESCOUT_NVD_API_KEY=
CVESCOUT_CLOUDFLARE_API_TOKEN=
CVESCOUT_NOTIFY_TIMEOUT=10
CVESCOUT_HTTPS=1
```

If you installed by hand, render the units and enable them:

```sh
flask --app cvescout install-units
```

Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cvescout
sudo journalctl -u cvescout -f
```

## Reverse proxy

Terminate TLS with Caddy, nginx, or another maintained proxy. Preserve `Host` and `X-Forwarded-Proto`. Set `CVESCOUT_HTTPS=1` so session cookies are Secure.

## Scheduled scans

The installer can enable the bundled timer with `--with-timer`. To do it later:

```sh
flask --app cvescout install-units                  # writes all three units
sudo systemctl enable --now cvescout-scan.timer
systemctl list-timers cvescout-scan.timer
```

Edit `/etc/systemd/system/cvescout-scan.service` to change `--kind`, then `sudo systemctl daemon-reload`.

Available kinds: `network`, `devices`, `ports`, `vulnerabilities`, `domains`. Add `--device 3` to limit port or vulnerability scans to one device id, or `--domain example.com` to scan one hostname. The command runs synchronously and exits non-zero on failure, so failed runs appear in `journalctl` and in the web UI job list.

```sh
flask --app cvescout scan --kind vulnerabilities
flask --app cvescout scan --kind domains --domain example.com
flask --app cvescout prune-history --days 30
```

Plain cron works too, but a timer gives you `Persistent=true` catch-up after downtime.

## Raspberry Pi Zero W tuning

The Zero W is a single-core ARMv6 board with 512 MB RAM and a 32-bit OS, so it lands on the `minimal` profile automatically: one scan worker, `-T3`, ports `1-1024,8080,8443`.

Recommended `/etc/cvescout.env` on that hardware:

```ini
CVESCOUT_NETWORKS=192.168.2.0/24
CVESCOUT_PROFILE=minimal
CVESCOUT_PORTS=22,23,53,80,443,445,548,554,631,1883,3306,3389,5000,5432,6379,8080,8443,9100
CVESCOUT_HISTORY_DAYS=90
CVESCOUT_HTTPS=0
# CVESCOUT_NVD_API_KEY=
```

Notes for this box:

- A 1024-port scan of a /24 takes roughly 30-90 minutes. Scan the short port list first, then widen once you know which hosts matter.
- Do not raise `CVESCOUT_WORKERS` above 1. Each Nmap process costs 10-20 MB, and 350 MB free RAM leaves no room for two.
- Use a DHCP reservation for the Pi. The service binds `127.0.0.1:5000`, so the address only matters for SSH and proxy bookmarks, but a changing lease breaks both.
- Store the database on the SD card and keep retention at 90 days or less; SQLite in WAL mode keeps steady but low write pressure.
- The distribution must ship Python 3.11+ (Raspberry Pi OS Bookworm or newer). Bullseye ships 3.9 and cannot run CVE Scout.

## Retention

Finished jobs, checks, domain checks, and audit events older than `CVESCOUT_HISTORY_DAYS` (default 90) are deleted at startup. Set it to `0` to keep everything, or run `flask --app cvescout prune-history` on a timer. Findings, devices, ports, and CVEs are never pruned.

## Sessions

Sessions expire after `CVESCOUT_SESSION_HOURS` (default 12). Any request refreshes the timer, so an idle browser is logged out but an active one is not.

## Backup

Stop service or use SQLite backup command:

```sh
sqlite3 instance/cvescout.sqlite3 ".backup '/safe/path/cvescout-backup.sqlite3'"
cp instance/secret_key /safe/path/secret_key
```

Database contains device addresses, public hostnames and edge IPs, service fingerprints, CVE/external findings, provider-check results, usernames, and audit history. Cookie values and user-supplied origin IPs are not stored. Protect backups and environment files containing API tokens.

## Upgrade

```sh
. /opt/cvescout/.venv/bin/activate
pip install --upgrade /opt/cvescout
sudo systemctl restart cvescout
```

The database schema is versioned with SQLite `user_version` and migrated automatically on startup, so upgrade with `pip install --upgrade` and a restart. Back up `instance/` first; migrations are not reversible.

## Troubleshooting

- `nmap is not installed`: install Nmap or set `CVESCOUT_NMAP`.
- `No scan network configured`: set `CVESCOUT_NETWORKS` explicitly.
- network too large: narrow CIDR or intentionally raise `CVESCOUT_MAX_HOSTS`.
- no CVEs: inspect device page for CPE values; no CPE means NVD correlation is skipped.
- NVD HTTP 403/429: add API key and wait before retrying.
- no KEV or EPSS values: run `flask --app cvescout refresh-intel`, or check outbound access to cisa.gov and api.first.org.
- too many product-only matches: narrow to `CVESCOUT_CVE_SOURCES=nvd`, or accept them as review leads.
- CIRCL slow or unreachable: scans continue with NVD results; failures are logged per source.
- check unsupported: no bounded non-destructive checker is mapped for that CVE.
- public hostname rejected as non-public: DNS returned loopback, private, link-local, reserved, or another non-global address.
- Cloudflare proxy not confirmed: Cloudflare nameservers were found but response headers/CNAME did not prove traffic crossed Cloudflare; confirm proxy status and origin firewall rules.
- public TLS failure: verify certificate chain/SNI at the edge and confirm port 443 is reachable.
- no notifications: confirm a channel is enabled under **Settings**, then use **Send test notification**; failures are listed per channel and recorded in the log.
- ntfy or gotify rejected: check the topic/app token; gotify tokens are sent as a query parameter and are redacted from logs.
- email API rejected: the payload is Resend-style, so adapt the endpoint or use a compatible gateway.
- Cloudflare check disabled: set `CVESCOUT_CLOUDFLARE_API_TOKEN` in service environment and restart.
- Cloudflare zone not found: token lacks access, zone is inactive, or hostname is not under an accessible zone.
- Cloudflare WAF unavailable: grant read-only ruleset/WAF permission if required; other checks can still complete.
- origin result `reachable`: restrict origin firewall/security-group ingress to provider networks or a trusted tunnel, then retest.
- origin result `not_reachable`: covers only the supplied addresses; check every origin IP and IPv6 path, then rescan the domain so comparisons use fresh edge data.
- origin check refused before the first domain scan: run **Rescan domain** first.

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app

from .version import __version__


class CloudflareCheckError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _api(path: str, params: dict | None = None, optional: bool = False):
    token = current_app.config["CLOUDFLARE_API_TOKEN"]
    if not token:
        raise CloudflareCheckError("Set CVESCOUT_CLOUDFLARE_API_TOKEN to run Cloudflare checks")
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    request = urllib.request.Request(
        f"{current_app.config['CLOUDFLARE_API'].rstrip('/')}/{path.lstrip('/')}{query}",
        headers={"Authorization": f"Bearer {token}", "User-Agent": f"CVE-Scout/{__version__}"},
    )
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=current_app.config["DOMAIN_CONNECT_TIMEOUT"]) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if optional and exc.code in {403, 404}:
            return None
        raise CloudflareCheckError(f"Cloudflare API returned HTTP {exc.code}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CloudflareCheckError(f"Cloudflare API request failed: {exc}") from exc
    if not payload.get("success"):
        if optional:
            return None
        errors = payload.get("errors") or []
        message = errors[0].get("message", "Cloudflare API request failed") if errors else "Cloudflare API request failed"
        raise CloudflareCheckError(message)
    return payload.get("result")


def _find_zone(name: str) -> dict:
    labels = name.split(".")
    for index in range(max(0, len(labels) - 10), len(labels) - 1):
        candidate = ".".join(labels[index:])
        zones = _api("zones", {"name": candidate, "status": "active", "per_page": 50})
        if zones:
            return zones[0]
    raise CloudflareCheckError("No active Cloudflare zone found for this hostname and API token")


def _check(key: str, status: str, severity: str, title: str, value: str, recommendation: str = "") -> dict:
    return {
        "key": key,
        "status": status,
        "severity": severity,
        "title": title,
        "value": value,
        "recommendation": recommendation,
    }


def _dns_check(records: list[dict]) -> dict:
    if not records:
        return _check(
            "dns.proxy",
            "fail",
            "high",
            "Cloudflare DNS record not found",
            "No A, AAAA, or CNAME record matched the hostname.",
            "Create the hostname in Cloudflare DNS and enable proxying when appropriate.",
        )
    unproxied = [record.get("type", "") for record in records if not record.get("proxied")]
    if unproxied:
        return _check(
            "dns.proxy",
            "fail",
            "high",
            "Cloudflare proxy is disabled",
            f"DNS-only record types: {', '.join(sorted(set(unproxied)))}",
            "Enable Cloudflare proxying and restrict origin ingress if this hostname should be protected.",
        )
    return _check("dns.proxy", "pass", "info", "Cloudflare proxy enabled", "All matching records are proxied.")


def _settings_checks(settings: dict) -> list[dict]:
    checks = []
    ssl_mode = str(settings.get("ssl", "unknown"))
    if ssl_mode == "strict":
        checks.append(_check("ssl.mode", "pass", "info", "SSL mode is Full (strict)", ssl_mode))
    else:
        severity = "high" if ssl_mode in {"off", "flexible"} else "medium"
        checks.append(
            _check(
                "ssl.mode",
                "fail",
                severity,
                "Cloudflare SSL mode is not Full (strict)",
                ssl_mode,
                "Use Full (strict) with a valid origin certificate.",
            )
        )

    always_https = str(settings.get("always_use_https", "unknown"))
    checks.append(
        _check(
            "https.redirect",
            "pass" if always_https == "on" else "fail",
            "info" if always_https == "on" else "medium",
            "Always Use HTTPS",
            always_https,
            "Enable Always Use HTTPS." if always_https != "on" else "",
        )
    )

    minimum_tls = str(settings.get("min_tls_version", "unknown"))
    tls_ok = minimum_tls in {"1.2", "1.3"}
    checks.append(
        _check(
            "tls.minimum",
            "pass" if tls_ok else "fail",
            "info" if tls_ok else "high",
            "Minimum TLS version",
            minimum_tls,
            "Set minimum TLS to 1.2 or newer." if not tls_ok else "",
        )
    )

    tls13 = str(settings.get("tls_1_3", "unknown"))
    tls13_ok = tls13 in {"on", "zrt"}
    checks.append(
        _check(
            "tls.1_3",
            "pass" if tls13_ok else "review",
            "info" if tls13_ok else "low",
            "TLS 1.3",
            tls13,
            "Enable TLS 1.3." if not tls13_ok else "",
        )
    )
    return checks


def check_cloudflare(name: str) -> tuple[str, str, dict]:
    zone = _find_zone(name)
    zone_id = zone["id"]
    records = _api(
        f"zones/{zone_id}/dns_records",
        {"name": name, "per_page": 100},
    )
    records = [record for record in records or [] if record.get("type") in {"A", "AAAA", "CNAME"}]
    settings_result = _api(f"zones/{zone_id}/settings")
    settings = {item.get("id"): item.get("value") for item in settings_result or []}
    dnssec = _api(f"zones/{zone_id}/dnssec") or {}
    waf = _api(
        f"zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint",
        optional=True,
    )

    checks = [_dns_check(records or []), *_settings_checks(settings)]
    dnssec_status = str(dnssec.get("status", "unknown"))
    checks.append(
        _check(
            "dnssec",
            "pass" if dnssec_status == "active" else "review",
            "info" if dnssec_status == "active" else "medium",
            "DNSSEC",
            dnssec_status,
            "Enable DNSSEC and publish the DS record at the registrar." if dnssec_status != "active" else "",
        )
    )
    if waf is None:
        checks.append(
            _check(
                "waf.managed",
                "unknown",
                "info",
                "Managed WAF visibility",
                "Unavailable with current token or plan.",
                "Grant read-only ruleset/WAF permission if this check is required.",
            )
        )
    else:
        rules = waf.get("rules", [])
        checks.append(
            _check(
                "waf.managed",
                "pass" if rules else "review",
                "info" if rules else "medium",
                "Managed WAF entrypoint",
                f"{len(rules)} rule entries found.",
                "Enable an appropriate managed ruleset." if not rules else "",
            )
        )

    high = sum(check["severity"] == "high" and check["status"] == "fail" for check in checks)
    review = sum(check["status"] in {"fail", "review"} for check in checks)
    result = "fail" if high else "review" if review else "pass"
    summary = f"Cloudflare configuration check: {high} high-risk and {review - high} review findings."
    details = {"zone": zone.get("name", ""), "checks": checks}
    return result, summary, details

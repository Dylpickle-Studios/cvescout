from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from .domain_scanner import probe_http, probe_https

MAX_ORIGINS = 4


class ProviderCheckError(RuntimeError):
    pass


def normalize_origin_ips(value: str) -> list[str]:
    """Parse a comma or whitespace separated list. Error text never echoes an address."""
    parts = [part for part in value.replace(",", " ").split() if part]
    if not parts:
        raise ProviderCheckError("Enter at least one public origin IP address")
    if len(parts) > MAX_ORIGINS:
        raise ProviderCheckError(f"Check at most {MAX_ORIGINS} origin IPs at a time")
    addresses = []
    for part in parts:
        try:
            address = ipaddress.ip_address(part)
        except ValueError as exc:
            raise ProviderCheckError("Every origin value must be an IP address") from exc
        if not address.is_global:
            raise ProviderCheckError("Origin checks require globally routable IP addresses")
        addresses.append(str(address))
    return list(dict.fromkeys(addresses))


def _probe_summary(probe: dict, edge: dict) -> dict:
    headers = probe.get("headers", {})
    edge_headers = edge.get("headers", {})
    body_hash = probe.get("body_sha256", "")
    edge_hash = edge.get("body_sha256", "")
    return {
        "reachable": bool(probe.get("ok")),
        "status": probe.get("status"),
        "server": headers.get("server", ""),
        "tls_version": probe.get("tls_version", ""),
        "certificate_trusted": probe.get("certificate_trusted"),
        "matches_edge_body": bool(body_hash and edge_hash and body_hash == edge_hash),
        "matches_edge_status": bool(probe.get("status") and probe.get("status") == edge.get("status")),
        "matches_edge_server": bool(
            headers.get("server") and headers.get("server") == edge_headers.get("server")
        ),
    }


def _age_note(scanned_at: str) -> str:
    if not scanned_at:
        return ""
    try:
        scanned = datetime.fromisoformat(scanned_at)
    except ValueError:
        return ""
    hours = max(0, round((datetime.now(UTC) - scanned).total_seconds() / 3600))
    if hours < 1:
        return " Compared against edge data recorded less than an hour ago."
    if hours < 48:
        return f" Compared against edge data recorded {hours} hours ago."
    return f" Compared against edge data recorded {hours // 24} days ago; rescan the domain for fresher comparison."


def check_origin(
    name: str,
    origin_ips: str,
    edge_https: dict,
    edge_http: dict,
    edge_scanned_at: str = "",
) -> tuple[str, str, dict]:
    addresses = normalize_origin_ips(origin_ips)
    candidates = []
    for address in addresses:
        trusted_https = probe_https(name, [address])
        https = trusted_https if trusted_https.get("ok") else probe_https(name, [address], verify_certificate=False)
        http = probe_http(name, [address])
        candidates.append(
            {
                "https": _probe_summary(https, edge_https),
                "http": _probe_summary(http, edge_http),
            }
        )

    answered = [candidate for candidate in candidates if candidate["https"]["reachable"] or candidate["http"]["reachable"]]
    details = {"tested": len(candidates), "candidates": candidates}
    note = _age_note(edge_scanned_at)
    if not answered:
        summary = (
            f"None of the {len(candidates)} supplied origins answered on ports 80 or 443 "
            f"using the public hostname.{note}"
        )
        return "not_reachable", summary, details

    protocols = sorted(
        {
            label
            for candidate in answered
            for label, key in (("HTTPS", "https"), ("HTTP", "http"))
            if candidate[key]["reachable"]
        }
    )
    matched = any(
        candidate[key]["matches_edge_body"]
        for candidate in answered
        for key in ("https", "http")
    )
    comparison = (
        " Response body matches the public edge."
        if matched
        else " Response differs from the public edge, so contents may still leak."
    )
    summary = (
        f"{len(answered)} of {len(candidates)} supplied origins answered directly over "
        f"{'/'.join(protocols)} with the public hostname.{comparison}"
        f" Restrict origin ingress to trusted edge networks if direct access is unintended.{note}"
    )
    return "reachable", summary, details

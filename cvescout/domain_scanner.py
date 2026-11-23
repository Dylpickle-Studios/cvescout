from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time

import dns.exception
import dns.resolver
from flask import current_app

from . import domain_cves
from .db import get_db, now
from .domain_findings import analyze_domain
from .version import __version__


class DomainScanError(RuntimeError):
    pass


SECURITY_TXT_PATH = "/.well-known/security.txt"

_META_TAG = re.compile(rb"<meta\s+[^>]*>", re.IGNORECASE)
_GENERATOR_NAME = re.compile(rb"""name\s*=\s*["']?generator["']?""", re.IGNORECASE)
_GENERATOR_CONTENT = re.compile(rb"""content\s*=\s*(?:["']([^"']+)["']|([^\s>]+))""", re.IGNORECASE)


def _generator_from_body(body: bytes) -> str:
    """Product/version from a meta generator tag (WordPress, Joomla, ...).

    Analyzed in memory like cookie values; only the resulting product/version
    string is kept, never the page content.
    """
    for tag in _META_TAG.findall(body):
        if _GENERATOR_NAME.search(tag):
            match = _GENERATOR_CONTENT.search(tag)
            if match:
                value = match.group(1) or match.group(2) or b""
                return value.decode("utf-8", "replace").strip()[:120]
    return ""


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if "://" in value or any(char in value for char in "/:@"):
        raise DomainScanError("Enter a hostname only, without scheme, path, port, or credentials")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainScanError("Invalid internationalized hostname") from exc
    if len(value) > 253 or "." not in value:
        raise DomainScanError("Enter a fully qualified public hostname")
    label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if not all(label.fullmatch(part) for part in value.split(".")):
        raise DomainScanError("Invalid hostname")
    return value


def resolve_public_addresses(name: str) -> list[str]:
    try:
        records = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DomainScanError(f"DNS resolution failed: {exc}") from exc
    addresses = sorted({str(record[4][0]) for record in records})
    if not addresses:
        raise DomainScanError("Hostname has no A or AAAA address")
    if len(addresses) > 16:
        raise DomainScanError("Hostname resolves to too many addresses")
    blocked = [address for address in addresses if not ipaddress.ip_address(address).is_global]
    if blocked:
        raise DomainScanError(f"Hostname resolves to non-public address: {blocked[0]}")
    return addresses


def _dns_values(resolver: dns.resolver.Resolver, name: str, record_type: str) -> list[str]:
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError):
        return []
    if not answer.rrset:
        return []
    values = []
    for item in answer:
        value = item.to_text().strip()
        if record_type == "TXT":
            value = value.replace('" "', "").strip('"')
        values.append(value.rstrip("."))
    return values


def collect_dns(name: str, addresses: list[str]) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = current_app.config["DOMAIN_CONNECT_TIMEOUT"]
    records = {
        "A": [address for address in addresses if ipaddress.ip_address(address).version == 4],
        "AAAA": [address for address in addresses if ipaddress.ip_address(address).version == 6],
    }
    for record_type in ("CNAME", "NS", "MX", "TXT", "CAA", "DS"):
        records[record_type] = _dns_values(resolver, name, record_type)
    records["DMARC"] = _dns_values(resolver, f"_dmarc.{name}", "TXT")
    return records


def _remaining(sock: socket.socket, deadline: float) -> None:
    """Cap each read at the probe's remaining budget so a trickle-feeding server
    cannot hold the single scan worker far beyond the configured timeout."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("public hostname probe exceeded its time budget")
    sock.settimeout(min(current_app.config["DOMAIN_CONNECT_TIMEOUT"], remaining))


def _http_response(sock: socket.socket, name: str, deadline: float, path: str = "/", capture_text: bool = False) -> dict:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: CVE-Scout/{__version__}\r\n"
        "Accept: text/html,*/*;q=0.8\r\nConnection: close\r\n\r\n"
    )
    _remaining(sock, deadline)
    sock.sendall(request.encode("ascii"))
    response = http.client.HTTPResponse(sock)
    _remaining(sock, deadline)
    response.begin()
    headers: dict[str, str] = {}
    cookies = []
    for key, value in response.getheaders():
        lowered = key.lower()
        if lowered == "set-cookie":
            cookies.append(value)
        elif lowered in headers:
            headers[lowered] = f"{headers[lowered]}, {value}"
        else:
            headers[lowered] = value
    limit = current_app.config["DOMAIN_MAX_BYTES"]
    body = bytearray()
    while len(body) <= limit:
        _remaining(sock, deadline)
        chunk = response.read(min(8192, limit + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    result = {
        "status": response.status,
        "reason": response.reason,
        "headers": headers,
        "set_cookies": cookies,
        "body_bytes": min(len(body), limit),
        "body_sha256": hashlib.sha256(bytes(body[:limit])).hexdigest(),
        "body_truncated": len(body) > limit,
    }
    if capture_text:
        # Analyzed in memory only (security.txt); _stored_probe strips it before persistence.
        result["body_text"] = bytes(body[:limit]).decode("utf-8", "replace")
    generator = _generator_from_body(bytes(body[:limit]))
    if generator:
        # Disclosed software metadata, the same class as the Server header.
        result["generator"] = generator
    return result


def _certificate_name(value) -> str:
    parts = []
    for group in value or ():
        for key, item in group:
            if key in {"commonName", "organizationName"}:
                parts.append(item)
    return ", ".join(parts)


def probe_https(
    name: str,
    addresses: list[str],
    verify_certificate: bool = True,
    deadline: float | None = None,
    path: str = "/",
    capture_text: bool = False,
) -> dict:
    # One total budget per probe: connect, TLS, headers, and body together.
    if deadline is None:
        deadline = time.monotonic() + current_app.config["DOMAIN_CONNECT_TIMEOUT"] * 4
    errors = []
    for address in addresses[:4]:
        if time.monotonic() >= deadline:
            errors.append(f"{address}: probe time budget exceeded")
            break
        try:
            context = ssl.create_default_context()
            if not verify_certificate:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection(
                    (address, 443), timeout=current_app.config["DOMAIN_CONNECT_TIMEOUT"]
                ) as raw,
                context.wrap_socket(raw, server_hostname=name) as secured,
            ):
                certificate = secured.getpeercert() or {}
                cipher_info = secured.cipher()
                result = _http_response(secured, name, deadline, path, capture_text)
                result.update(
                    {
                        "ok": True,
                        "address": address,
                        "tls_version": secured.version() or "",
                        "cipher": cipher_info[0] if cipher_info else "",
                        "certificate_subject": _certificate_name(certificate.get("subject")),
                        "certificate_issuer": _certificate_name(certificate.get("issuer")),
                        "certificate_expires": certificate.get("notAfter", ""),
                        "certificate_trusted": verify_certificate,
                    }
                )
                return result
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            errors.append(f"{address}: {exc}")
    return {"ok": False, "error": "; ".join(errors[:2]) or "HTTPS connection failed"}


def probe_http(
    name: str,
    addresses: list[str],
    deadline: float | None = None,
    path: str = "/",
    capture_text: bool = False,
) -> dict:
    if deadline is None:
        deadline = time.monotonic() + current_app.config["DOMAIN_CONNECT_TIMEOUT"] * 4
    errors = []
    for address in addresses[:4]:
        if time.monotonic() >= deadline:
            errors.append(f"{address}: probe time budget exceeded")
            break
        try:
            with socket.create_connection(
                (address, 80), timeout=current_app.config["DOMAIN_CONNECT_TIMEOUT"]
            ) as connection:
                result = _http_response(connection, name, deadline, path, capture_text)
                result.update({"ok": True, "address": address})
                return result
        except (OSError, http.client.HTTPException) as exc:
            errors.append(f"{address}: {exc}")
    return {"ok": False, "error": "; ".join(errors[:2]) or "HTTP connection failed"}


def _stored_probe(probe: dict) -> dict:
    stored = {
        **probe,
        "set_cookies": [cookie.split("=", 1)[0] for cookie in probe.get("set_cookies", [])],
    }
    # Captured text (security.txt) is analyzed in memory and never persisted.
    stored.pop("body_text", None)
    return stored


def probe_security_txt(name: str, addresses: list[str], prefer_https: bool) -> dict:
    """One bounded GET of /.well-known/security.txt (RFC 9116), HTTPS first."""
    if prefer_https:
        probe = probe_https(name, addresses, path=SECURITY_TXT_PATH, capture_text=True)
        if probe.get("ok"):
            return probe
    return probe_http(name, addresses, path=SECURITY_TXT_PATH, capture_text=True)


def _replace_findings(db, domain_id: int, findings: list[dict], timestamp: str) -> list[str]:
    """Upsert findings and return the labels of high/medium ones that are new since the last scan."""
    # Only open findings count as "already known": a resolved finding that comes
    # back is new again and must alert, matching the CVE lifecycle.
    previous = {
        row["finding_key"]
        for row in db.execute(
            "SELECT finding_key FROM domain_findings WHERE domain_id=? AND resolved_at IS NULL", (domain_id,)
        )
    }
    for finding in findings:
        db.execute(
            "INSERT INTO domain_findings(domain_id,finding_key,severity,category,title,detail,evidence,remediation,"
            "last_seen,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(domain_id,finding_key) DO UPDATE SET "
            "severity=excluded.severity,category=excluded.category,title=excluded.title,detail=excluded.detail,"
            "evidence=excluded.evidence,remediation=excluded.remediation,last_seen=excluded.last_seen,"
            "resolved_at=NULL",
            (domain_id, *finding.values(), timestamp, timestamp),
        )
    keys = [finding["finding_key"] for finding in findings]
    if not keys:
        db.execute(
            "UPDATE domain_findings SET resolved_at=? WHERE domain_id=? AND resolved_at IS NULL",
            (timestamp, domain_id),
        )
        return []
    placeholders = ",".join("?" for _ in keys)
    db.execute(
        f"UPDATE domain_findings SET resolved_at=? WHERE domain_id=? AND resolved_at IS NULL "
        f"AND finding_key NOT IN ({placeholders})",
        (timestamp, domain_id, *keys),
    )
    return [
        f"{finding['severity']}: {finding['title']}"
        for finding in findings
        if finding["finding_key"] not in previous and finding["severity"] in {"high", "medium"}
    ]


def scan_domain(domain_id: int) -> tuple[int, list[str]]:
    """Scan one hostname. Returns (total findings, labels of new high/medium findings)."""
    db = get_db()
    domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not domain:
        raise DomainScanError("Domain not found")
    timestamp = now()
    try:
        name = normalize_domain(domain["name"])
        addresses = resolve_public_addresses(name)
        records = collect_dns(name, addresses)
        https = probe_https(name, addresses)
        http = probe_http(name, addresses)
        security_txt = None
        if https.get("ok") or http.get("ok"):
            security_txt = probe_security_txt(name, addresses, https.get("ok", False))
        provider, findings = analyze_domain(records, https, http, security_txt=security_txt, name=name)
        software = domain_cves.extract_software(https, http)
        if software:
            try:
                findings.extend(domain_cves.correlate_software(software))
            except Exception as exc:  # noqa: BLE001 - CVE enrichment must never lose the edge scan.
                current_app.logger.warning("Domain CVE correlation failed for %s: %s", name, exc)
        highest = {finding["severity"] for finding in findings}
        status = "high" if "high" in highest else "warning" if highest & {"medium", "low"} else "ok"
        new_findings = _replace_findings(db, domain_id, findings, timestamp)
        db.execute(
            "UPDATE domains SET provider=?,status=?,addresses=?,dns_summary=?,tls_summary=?,http_summary=?,last_scanned=? WHERE id=?",
            (
                provider,
                status,
                json.dumps(addresses),
                json.dumps(records),
                json.dumps(_stored_probe(https)),
                json.dumps(_stored_probe(http)),
                timestamp,
                domain_id,
            ),
        )
        db.commit()
        return len(findings), new_findings
    except Exception:
        # last_scanned stays untouched: a failed scan observed nothing, so old findings must not look fresh.
        db.execute("UPDATE domains SET status='error' WHERE id=?", (domain_id,))
        db.commit()
        raise

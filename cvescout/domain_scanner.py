from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl

import dns.exception
import dns.resolver
from flask import current_app

from .db import get_db, now
from .domain_findings import analyze_domain
from .version import __version__


class DomainScanError(RuntimeError):
    pass


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
    addresses = sorted({record[4][0] for record in records})
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


def _http_response(sock: socket.socket, name: str) -> dict:
    request = (
        f"GET / HTTP/1.1\r\nHost: {name}\r\nUser-Agent: CVE-Scout/{__version__}\r\n"
        "Accept: text/html,*/*;q=0.8\r\nConnection: close\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = http.client.HTTPResponse(sock)
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
    body = response.read(limit + 1)
    return {
        "status": response.status,
        "reason": response.reason,
        "headers": headers,
        "set_cookies": cookies,
        "body_bytes": min(len(body), limit),
        "body_sha256": hashlib.sha256(body[:limit]).hexdigest(),
        "body_truncated": len(body) > limit,
    }


def _certificate_name(value) -> str:
    parts = []
    for group in value or ():
        for key, item in group:
            if key in {"commonName", "organizationName"}:
                parts.append(item)
    return ", ".join(parts)


def probe_https(name: str, addresses: list[str], verify_certificate: bool = True) -> dict:
    errors = []
    for address in addresses[:4]:
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
                certificate = secured.getpeercert()
                result = _http_response(secured, name)
                result.update(
                    {
                        "ok": True,
                        "address": address,
                        "tls_version": secured.version() or "",
                        "cipher": secured.cipher()[0] if secured.cipher() else "",
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


def probe_http(name: str, addresses: list[str]) -> dict:
    errors = []
    for address in addresses[:4]:
        try:
            with socket.create_connection(
                (address, 80), timeout=current_app.config["DOMAIN_CONNECT_TIMEOUT"]
            ) as connection:
                result = _http_response(connection, name)
                result.update({"ok": True, "address": address})
                return result
        except (OSError, http.client.HTTPException) as exc:
            errors.append(f"{address}: {exc}")
    return {"ok": False, "error": "; ".join(errors[:2]) or "HTTP connection failed"}


def _stored_probe(probe: dict) -> dict:
    return {
        **probe,
        "set_cookies": [cookie.split("=", 1)[0] for cookie in probe.get("set_cookies", [])],
    }


def _replace_findings(db, domain_id: int, findings: list[dict], timestamp: str) -> list[str]:
    """Upsert findings and return the labels of high/medium ones that are new since the last scan."""
    previous = {
        row["finding_key"]
        for row in db.execute("SELECT finding_key FROM domain_findings WHERE domain_id=?", (domain_id,))
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
        provider, findings = analyze_domain(records, https, http)
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

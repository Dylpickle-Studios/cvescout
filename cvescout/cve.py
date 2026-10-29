from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta

from flask import current_app

from . import circl, exploit_intel
from .db import get_db, now
from .version import __version__

_request_lock = threading.Lock()
_last_request = 0.0


def normalize_cpe(value: str) -> str:
    value = value.strip()
    if value.startswith("cpe:2.3:"):
        return value
    if not value.startswith("cpe:/"):
        raise ValueError("Unsupported CPE format")
    parts = value[5:].split(":")
    # shortcut: legacy packed-edition CPEs are not expanded, upgrade if nmap emits them in practice.
    parts.extend(["*"] * (11 - len(parts)))
    return "cpe:2.3:" + ":".join(parts[:11])


def _metric(cve: dict) -> tuple[str, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN")), data.get("baseScore")
    return "UNKNOWN", None


def _parse_response(payload: dict) -> list[dict]:
    results = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        severity, score = _metric(cve)
        results.append(
            {
                "cve_id": cve_id,
                "source": "NVD",
                "severity": severity,
                "score": score,
                "summary": summary,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )
    return results


def _cached(cpe: str) -> tuple[list[dict] | None, bool]:
    row = get_db().execute("SELECT payload,fetched_at FROM cve_cache WHERE cpe=?", (cpe,)).fetchone()
    if not row:
        return None, False
    fetched = datetime.fromisoformat(row["fetched_at"])
    fresh = fetched >= datetime.now(UTC) - timedelta(hours=current_app.config["NVD_CACHE_HOURS"])
    return json.loads(row["payload"]), fresh


def lookup_cpe(cpe: str) -> list[dict]:
    global _last_request
    normalized = normalize_cpe(cpe)
    cached, fresh = _cached(normalized)
    if fresh:
        return cached or []

    params = urllib.parse.urlencode({"cpeName": normalized, "resultsPerPage": 2000})
    request = urllib.request.Request(
        f"{current_app.config['NVD_API']}?{params}&isVulnerable&noRejected",
        headers={"User-Agent": f"CVE-Scout/{__version__}", **({"apiKey": current_app.config["NVD_API_KEY"]} if current_app.config["NVD_API_KEY"] else {})},
    )
    delay = 0.7 if current_app.config["NVD_API_KEY"] else 6.1
    try:
        with _request_lock:
            wait = delay - (time.monotonic() - _last_request)
            if wait > 0:
                time.sleep(wait)
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
            _last_request = time.monotonic()
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        if cached is not None:
            return cached
        raise RuntimeError(f"NVD lookup failed for {normalized}: {exc}") from exc

    results = _parse_response(payload)
    db = get_db()
    db.execute(
        "INSERT INTO cve_cache(cpe,payload,fetched_at) VALUES(?,?,?) "
        "ON CONFLICT(cpe) DO UPDATE SET payload=excluded.payload,fetched_at=excluded.fetched_at",
        (normalized, json.dumps(results), now()),
    )
    db.commit()
    return results


def _port_version(port) -> str:
    """Best-effort version for CIRCL range checks: prefer the CPE, fall back to Nmap."""
    for cpe in [value.strip() for value in port["cpe"].splitlines() if value.strip()]:
        try:
            fields = normalize_cpe(cpe).split(":")
        except ValueError:
            continue
        if len(fields) > 5 and fields[5] not in {"*", "-"}:
            return fields[5]
    return port["version"] or ""


def _merge_sources(cpe: str, version: str, sources: list[str]) -> list[dict]:
    """Query every enabled source for one CPE and keep the strongest claim per CVE."""
    merged: dict[str, dict] = {}
    for source in sources:
        try:
            if source == "nvd":
                findings = [{**item, "match_type": "exact"} for item in lookup_cpe(cpe)]
            elif source == "circl":
                findings = circl.lookup_cpe(cpe, version)
            else:
                continue
        except (RuntimeError, circl.CirclError) as exc:
            # One source being down must not lose the other one's results.
            current_app.logger.warning("CVE source %s failed for %s: %s", source, cpe, exc)
            continue
        for finding in findings:
            existing = merged.get(finding["cve_id"])
            if existing is None or _rank(finding) > _rank(existing):
                merged[finding["cve_id"]] = finding
    return list(merged.values())


def _rank(finding: dict) -> tuple[int, int, float]:
    """Higher is better: exact version match, then a known severity, then a score."""
    confidence = 0 if finding.get("match_type") == "product" else 1
    scored = 1 if finding.get("score") is not None else 0
    return confidence, scored, float(finding.get("score") or 0)


def correlate_port(port_id: int) -> tuple[int, list[str]]:
    """Return (matches stored, labels for high-severity CVEs that are new since the last run)."""
    db = get_db()
    port = db.execute("SELECT * FROM ports WHERE id=?", (port_id,)).fetchone()
    if not port:
        return 0, []
    known = {
        row["cve_id"]
        for row in db.execute(
            "SELECT cve_id FROM vulnerabilities WHERE port_id=? AND resolved_at IS NULL", (port_id,)
        )
    }
    sources = current_app.config["CVE_SOURCES"]
    version = _port_version(port)
    cpes = [value.strip() for value in port["cpe"].splitlines() if value.strip()]
    found: dict[str, dict] = {}
    for cpe in cpes:
        for vulnerability in _merge_sources(cpe, version, sources):
            existing = found.get(vulnerability["cve_id"])
            if existing is None or _rank(vulnerability) > _rank(existing):
                found[vulnerability["cve_id"]] = vulnerability
    timestamp = now()
    for vulnerability in found.values():
        db.execute(
            "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen,match_type,first_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(port_id,cve_id) DO UPDATE SET source=excluded.source,severity=excluded.severity,"
            "score=excluded.score,summary=excluded.summary,url=excluded.url,last_seen=excluded.last_seen,"
            "match_type=excluded.match_type,resolved_at=NULL",
            (
                port_id,
                vulnerability["cve_id"],
                vulnerability["source"],
                vulnerability["severity"],
                vulnerability["score"],
                vulnerability["summary"],
                vulnerability["url"],
                timestamp,
                vulnerability.get("match_type", "exact"),
                timestamp,
            ),
        )
    # Findings that vanished are resolved, not deleted, so a report can show what changed.
    if found:
        placeholders = ",".join("?" for _ in found)
        db.execute(
            f"UPDATE vulnerabilities SET resolved_at=? WHERE port_id=? AND resolved_at IS NULL "
            f"AND cve_id NOT IN ({placeholders})",
            (timestamp, port_id, *found.keys()),
        )
    else:
        db.execute(
            "UPDATE vulnerabilities SET resolved_at=? WHERE port_id=? AND resolved_at IS NULL",
            (timestamp, port_id),
        )
    db.commit()
    # Product-only matches are leads, not confirmed versions, so they never raise an alert.
    new_high = [
        f"{vulnerability['cve_id']} {vulnerability['severity']} on port {port['port']}"
        for cve_id, vulnerability in found.items()
        if cve_id not in known
        and vulnerability["severity"] in {"HIGH", "CRITICAL"}
        and vulnerability.get("match_type") != "product"
    ]
    return len(found), new_high


def correlate_all(device_id: int | None = None) -> tuple[int, int, list[str]]:
    db = get_db()
    if device_id:
        rows = db.execute("SELECT ports.id FROM ports WHERE device_id=? ORDER BY ports.id", (device_id,)).fetchall()
    else:
        rows = db.execute("SELECT id FROM ports ORDER BY id").fetchall()
    total = 0
    new_high: list[str] = []
    for row in rows:
        matches, fresh = correlate_port(row["id"])
        total += matches
        new_high.extend(fresh)
    cve_ids = [
        item["cve_id"]
        for item in db.execute(
            "SELECT DISTINCT cve_id FROM vulnerabilities"
            + (" WHERE port_id IN (SELECT id FROM ports WHERE device_id=?)" if device_id else ""),
            (device_id,) if device_id else (),
        )
    ]
    exploit_intel.refresh_all(cve_ids)
    return len(rows), total, new_high

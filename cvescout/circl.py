"""CIRCL Vulnerability-Lookup as a second CVE source.

NVD only annotates CVEs it chooses to enrich, so a real CVE can be missing from an
NVD CPE lookup. Vulnerability-Lookup aggregates the official CVE List (and therefore
CISA Vulnrichment) and offers a CPE search, which recovers that recall.

Trade-off: its CPE search matches vendor and product, not an exact version, so matches
are classified locally:

- ``version``  the CPE version falls inside a range the CVE record declares
- ``product``  the CVE affects this product but the version is unknown or outside the
               declared ranges; stored for review and never used to raise an alert

CPE 2.2 input is rejected by the API, so callers must pass the normalized 2.3 form.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app

from .db import get_db, now
from .version import __version__

CACHE_PREFIX = "circl:"
CIRCL_PAGE_SIZE = 100
_SEPARATORS = re.compile(r"\s*(?:-|–|—|through|to|until)\s*", re.IGNORECASE)
_request_lock = threading.Lock()
_last_request = 0.0


class CirclError(RuntimeError):
    pass


def _to_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(value))[:4]
    return tuple(int(part) for part in parts) if parts else ()


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    left_padded = left + (0,) * (width - len(left))
    right_padded = right + (0,) * (width - len(right))
    return (left_padded > right_padded) - (left_padded < right_padded)


def version_in_range(probe: str, label: str) -> bool:
    """True when `probe` looks covered by a CVE version label such as "0.5.6 - 1.13.2"."""
    current = _to_tuple(probe)
    if not current or not label:
        return False
    bounds = [part for part in _SEPARATORS.split(label.strip()) if part.strip()]
    parsed = [_to_tuple(part) for part in bounds]
    parsed = [item for item in parsed if item]
    if not parsed:
        return False
    if len(parsed) == 1:
        return _compare(current, parsed[0]) == 0 or str(probe).startswith(f"{bounds[0].strip()}.")
    return _compare(parsed[0], current) <= 0 <= _compare(parsed[-1], current)


def _blocks(record: dict, container: str) -> list[dict]:
    """CVE 5.x containers are usually dicts but the schema also allows a list."""
    value = record.get("containers", {}).get(container)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [block for block in value if isinstance(block, dict)]
    return []


def _affected_ranges(record: dict) -> list[str]:
    ranges = []
    for container in ("cna", "adp"):
        for block in _blocks(record, container):
            for affected in block.get("affected", []) or []:
                for entry in affected.get("versions", []) or []:
                    if entry.get("status", "affected") != "affected":
                        continue
                    label = entry.get("version") or ""
                    if entry.get("lessThan"):
                        label = f"{label} - {entry['lessThan']}"
                    if label and label != "n/a":
                        ranges.append(label)
    return ranges


def _severity(record: dict) -> tuple[str, float | None]:
    for container in ("cna", "adp"):
        for block in _blocks(record, container):
            for metric in block.get("metrics", []) or []:
                for key, value in metric.items():
                    if not key.startswith("cvss") or not isinstance(value, dict):
                        continue
                    score = value.get("baseScore")
                    severity = value.get("baseSeverity")
                    if score is None:
                        continue
                    if not severity:
                        severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
                    return str(severity).upper(), float(score)
    return "UNKNOWN", None


def _summary(record: dict) -> str:
    for container in ("cna", "adp"):
        for block in _blocks(record, container):
            for description in block.get("descriptions", []) or []:
                if str(description.get("lang", "")).lower().startswith("en"):
                    return description.get("value", "")
    return ""


def parse_records(records: list[dict], version: str) -> list[dict]:
    """Turn CVE-5.x records into the finding shape used by the rest of the app."""
    findings = []
    for record in records:
        cve_id = record.get("cveMetadata", {}).get("cveId")
        if not cve_id:
            continue
        severity, score = _severity(record)
        ranges = _affected_ranges(record)
        matched = bool(version) and any(version_in_range(version, label) for label in ranges)
        findings.append(
            {
                "cve_id": cve_id,
                "source": "CIRCL",
                "severity": severity,
                "score": score,
                "summary": _summary(record),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "match_type": "version" if matched else "product",
            }
        )
    return findings


def _cached(key: str) -> tuple[list[dict] | None, bool]:
    row = get_db().execute("SELECT payload,fetched_at FROM cve_cache WHERE cpe=?", (key,)).fetchone()
    if not row:
        return None, False
    from datetime import UTC, datetime, timedelta

    fetched = datetime.fromisoformat(row["fetched_at"])
    fresh = fetched >= datetime.now(UTC) - timedelta(hours=current_app.config["NVD_CACHE_HOURS"])
    return json.loads(row["payload"]), fresh


def lookup_cpe(cpe: str, version: str) -> list[dict]:
    """Return CIRCL findings for an exact CPE. Raises CirclError when unavailable and uncached."""
    key = f"{CACHE_PREFIX}{cpe}"
    cached, fresh = _cached(key)
    if fresh:
        return cached or []

    url = (
        f"{current_app.config['CIRCL_API'].rstrip('/')}/vulnerability/cpesearch/"
        f"{urllib.parse.quote(cpe, safe='')}?per_page={CIRCL_PAGE_SIZE}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": f"CVE-Scout/{__version__}"})
    global _last_request
    with _request_lock:
        wait = 1.1 - (time.monotonic() - _last_request)
        if wait > 0:
            time.sleep(wait)
        try:
            with urllib.request.urlopen(request, timeout=current_app.config["DOMAIN_CONNECT_TIMEOUT"]) as response:
                payload = json.load(response)
        except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            if cached is not None:
                return cached
            raise CirclError(f"CIRCL lookup failed: {exc}") from exc
        _last_request = time.monotonic()

    records = payload.get("cvelistv5") or []
    if len(records) >= CIRCL_PAGE_SIZE:
        # shortcut: only the first page is read, so very common products can hide CVEs. Deepen only if it matters.
        current_app.logger.warning("CIRCL returned a full page for %s; older CVEs may be missing", cpe)
    findings = parse_records(records, version)
    db = get_db()
    db.execute(
        "INSERT INTO cve_cache(cpe,payload,fetched_at) VALUES(?,?,?) "
        "ON CONFLICT(cpe) DO UPDATE SET payload=excluded.payload,fetched_at=excluded.fetched_at",
        (key, json.dumps(findings), now()),
    )
    db.commit()
    return findings

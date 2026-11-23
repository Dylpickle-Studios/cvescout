"""Explicit, bounded verification of matched CVEs.

Two check kinds, both user-initiated and audited:

- script: a hard-coded allowlist of non-destructive Nmap NSE detectors.
  Admission criteria: shipped with Nmap, no code execution on the target, no
  state change, no crash risk. Scripts that run commands on the target
  (http-vuln-cve2012-1823) or can crash it (smb-vuln-ms08-067,
  http-vuln-cve2015-1635) are deliberately excluded even though they detect
  real CVEs.
- version: for version-aware matches without a script, re-fingerprint one port
  and re-correlate it against the CVE sources. This confirms whether the
  installed version still falls in the CVE's affected range. It sends no
  payloads at all and is not proof of exploitability.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET

from flask import current_app

from . import cve, scanner
from .db import get_db, now
from .scanner import ScanError, validate_target

CHECKS: dict[str, dict] = {
    "CVE-2014-0160": {
        "script": "ssl-heartbleed",
        "title": "Heartbleed",
        "description": "Sends a malformed TLS heartbeat request and checks whether the server leaks memory in its response (read-only).",
    },
    "CVE-2014-0224": {
        "script": "ssl-ccs-injection",
        "title": "OpenSSL CCS injection",
        "description": "Sends an early ChangeCipherSpec message and checks whether the server accepts it (read-only).",
    },
    "CVE-2014-3566": {
        "script": "ssl-poodle",
        "title": "POODLE",
        "description": "Checks whether the server still accepts SSLv3 with CBC ciphers (protocol negotiation only).",
    },
    "CVE-2015-4000": {
        "script": "ssl-dh-params",
        "title": "Logjam / weak DH",
        "description": "Inspects the server's Diffie-Hellman parameters for export-grade or common primes (read-only).",
    },
    "CVE-2012-0002": {
        "script": "rdp-vuln-ms12-020",
        "title": "MS12-020 RDP",
        "description": "Checks the MS12-020 patch state via RDP channel joins; the script explicitly avoids crashing the target.",
    },
    "CVE-2012-0152": {
        "script": "rdp-vuln-ms12-020",
        "title": "MS12-020 RDP DoS",
        "description": "Checks the MS12-020 patch state via RDP channel joins; the script explicitly avoids crashing the target.",
    },
}
# MS17-010 patched this whole CVE family; the detector reports the unpatched state.
for _cve in ("CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148"):
    CHECKS[_cve] = {
        "script": "smb-vuln-ms17-010",
        "title": "EternalBlue (MS17-010)",
        "description": "Connects to IPC$ and checks the SMBv1 transaction error codes that reveal the MS17-010 patch state (read-only).",
    }

# Kept for callers and templates that only need the CVE -> script mapping.
SAFE_NSE_CHECKS = {cve_id: info["script"] for cve_id, info in CHECKS.items()}

_script_availability: dict[str, bool] = {}

RESULT_LABELS = {
    "vulnerable": "Vulnerable",
    "not_vulnerable": "Not vulnerable",
    "inconclusive": "Inconclusive",
    "unsupported": "No safe checker",
    "version_confirmed": "Version confirmed",
    "version_not_reproduced": "Not reproduced",
}


def checker_for(cve_id: str) -> str | None:
    return SAFE_NSE_CHECKS.get(cve_id.upper())


def check_info(cve_id: str) -> dict | None:
    return CHECKS.get(cve_id.upper())


def script_available(script: str) -> bool:
    """True when this Nmap build ships the detector. Cached per process."""
    if script not in _script_availability:
        try:
            result = subprocess.run(
                [current_app.config["NMAP"], "--script-help", script],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            _script_availability[script] = result.returncode == 0 and script in result.stdout
        except (OSError, subprocess.TimeoutExpired):
            _script_availability[script] = False
    return _script_availability[script]


def _classify(details: str) -> str:
    """Prefer the structured 'State:' lines NSE vuln scripts emit; fall back to
    substring matching for older output formats."""
    states = [state.strip().upper() for state in re.findall(r"State:\s*([^\n(]+)", details)]
    if states:
        if any("VULNERABLE" in state and "NOT VULNERABLE" not in state for state in states):
            return "vulnerable"
        if all("NOT VULNERABLE" in state for state in states):
            return "not_vulnerable"
    upper = details.upper()
    if "NOT VULNERABLE" in upper:
        return "not_vulnerable"
    if "VULNERABLE" in upper:
        return "vulnerable"
    return "inconclusive"


def run_check(
    address: str,
    port: int,
    cve_id: str,
    port_id: int | None = None,
    match_type: str = "",
    protocol: str = "tcp",
) -> tuple[str, str]:
    script = checker_for(cve_id)
    if script:
        return run_script_check(address, port, script, protocol)
    if port_id is not None and match_type in {"version", "exact"}:
        return run_version_check(port_id, cve_id)
    return (
        "unsupported",
        (
            "No non-destructive active checker exists for this CVE. This is a product-only lead: "
            "confirm the installed version against the CVE's affected range, or rescan after upgrading the service."
        ),
    )


def run_script_check(address: str, port: int, script: str, protocol: str = "tcp") -> tuple[str, str]:
    if not script_available(script):
        return (
            "inconclusive",
            f"The {script} detector is not installed in this Nmap build. Update Nmap (7.x with NSE scripts) to run this check.",
        )
    target = validate_target(address)
    port_args = ["-sU", "-p", f"U:{int(port)}"] if protocol == "udp" else ["-p", str(int(port))]
    command = [
        current_app.config["NMAP"],
        "-Pn",
        *port_args,
        "--script",
        script,
        "--script-timeout",
        "60s",
        target,
        "-oX",
        "-",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=current_app.config["CHECK_TIMEOUT"],
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScanError("nmap is not installed or CVESCOUT_NMAP is wrong") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Vulnerability check timed out") from exc
    if result.returncode != 0:
        raise ScanError(result.stderr.strip() or f"nmap exited with {result.returncode}")
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise ScanError("nmap returned invalid XML") from exc
    outputs = [node.get("output", "") for node in root.findall(".//script") if node.get("id") == script]
    details = "\n".join(outputs).strip() or "Checker returned no finding"
    return _classify(details), details


def run_version_check(port_id: int, cve_id: str) -> tuple[str, str]:
    """Re-fingerprint one port and re-correlate it; report whether this CVE still matches.

    Safe for any CVE: it is a service probe plus the same cached source lookups a
    vulnerability scan uses. A confirmation is version-based, not proof of exploitability.
    """
    db = get_db()
    port = db.execute("SELECT * FROM ports WHERE id=?", (port_id,)).fetchone()
    if not port:
        return "inconclusive", "Port record no longer exists"
    device = db.execute("SELECT address FROM devices WHERE id=?", (port["device_id"],)).fetchone()
    if not device:
        return "inconclusive", "Device record no longer exists"
    address = validate_target(device["address"])
    previous = f"{port['product']} {port['version']}".strip() or "no version"
    port_args = ["-sU", "-p", f"U:{port['port']}"] if port["protocol"] == "udp" else ["-p", str(port["port"])]
    try:
        root = scanner._run_nmap(
            ["-Pn", "-sV", "--version-light", current_app.config["NMAP_TIMING"], *port_args, address]
        )
    except ScanError as exc:
        return "inconclusive", f"Version re-probe failed: {exc}"
    records = scanner._port_records(root)
    fresh = next((r for r in records if r["port"] == port["port"] and r["protocol"] == port["protocol"]), None)
    if fresh is None:
        return "inconclusive", "Port did not report an open service on re-probe; the version cannot be re-verified"
    db.execute(
        "UPDATE ports SET service=?,product=?,version=?,extra_info=?,cpe=?,last_seen=? WHERE id=?",
        (fresh["service"], fresh["product"], fresh["version"], fresh["extra_info"], fresh["cpe"], now(), port_id),
    )
    db.commit()
    current = f"{fresh['product']} {fresh['version']}".strip() or "no version"
    # Re-correlate with the fresh fingerprint; source failures keep existing findings.
    cve.correlate_port(port_id)
    row = db.execute(
        "SELECT match_type,resolved_at FROM vulnerabilities WHERE port_id=? AND cve_id=?",
        (port_id, cve_id),
    ).fetchone()
    if row is None or row["resolved_at"] is not None:
        return (
            "version_not_reproduced",
            (
                f"{cve_id} no longer matches the fresh fingerprint ({current}; previously {previous}). "
                "The service was upgraded, reconfigured, or the original match was a false positive."
            ),
        )
    if row["match_type"] in {"version", "exact"}:
        return (
            "version_confirmed",
            (
                f"The fresh fingerprint ({current}) still matches {cve_id} with {row['match_type']} confidence. "
                "Version-based confirmation, not proof of exploitability; check the vendor advisory for fixed versions."
            ),
        )
    return (
        "inconclusive",
        f"{cve_id} now matches only at product level for the fresh fingerprint ({current}); confirm the exact version manually.",
    )

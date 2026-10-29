from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET

from flask import current_app

from .scanner import ScanError, validate_target

SAFE_NSE_CHECKS = {
    "CVE-2014-0160": "ssl-heartbleed",
    "CVE-2014-0224": "ssl-ccs-injection",
    "CVE-2014-3566": "ssl-poodle",
    "CVE-2015-4000": "ssl-dh-params",
}


def checker_for(cve_id: str) -> str | None:
    return SAFE_NSE_CHECKS.get(cve_id.upper())


def run_check(address: str, port: int, cve_id: str) -> tuple[str, str]:
    script = checker_for(cve_id)
    if not script:
        return "unsupported", "No non-destructive checker is available for this CVE"
    target = validate_target(address)
    command = [
        current_app.config["NMAP"],
        "-Pn",
        "-p",
        str(int(port)),
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
    upper = details.upper()
    if "NOT VULNERABLE" in upper:
        return "not_vulnerable", details
    if "VULNERABLE" in upper:
        return "vulnerable", details
    return "inconclusive", details

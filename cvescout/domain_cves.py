"""Passive CVE correlation for public hostnames.

Software disclosed in the Server and X-Powered-By headers is mapped to CPEs
through an explicit product table (no guessing), then correlated with the same
cached CVE sources used for local ports. Only the header-derived CPE leaves the
network; response bodies are never used for matching or stored.

Header versions can be masked or backported by distributions, so matches carry
the same version/product confidence labels as local findings, and product-only
leads never raise alerts.
"""

from __future__ import annotations

import re

from flask import current_app

from . import circl, cve, exploit_intel

# Explicit product -> CPE mappings. Only products with unambiguous NVD/CIRCL
# CPE naming are listed; anything else is ignored rather than guessed.
SOFTWARE_CPE = {
    "nginx": "cpe:/a:nginx:nginx",
    "apache": "cpe:/a:apache:http_server",
    "microsoft-iis": "cpe:/a:microsoft:internet_information_services",
    "openresty": "cpe:/a:openresty:openresty",
    "lighttpd": "cpe:/a:lighttpd:lighttpd",
    "php": "cpe:/a:php:php",
    "wordpress": "cpe:/a:wordpress:wordpress",
    "drupal": "cpe:/a:drupal:drupal",
    # The CPE dictionary escapes the exclamation mark in Joomla's product name.
    "joomla": "cpe:/a:joomla:joomla\\!",
}

_VERSION = re.compile(r"^\d+(?:\.\d+)+")
_GENERATOR_VERSION = re.compile(r"^\d+(?:\.\d+)*")

SEVERITY_MAP = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}


def _add_generator(value: str, header: str, seen: dict[tuple[str, str], dict]) -> None:
    """Parse 'WordPress 6.2.2' / 'Drupal 10 (...)' / 'Joomla! 3.9' style strings."""
    name, _, version = value.strip().partition(" ")
    name = name.lower().rstrip("!")
    if name not in SOFTWARE_CPE:
        return
    match = _GENERATOR_VERSION.match(version)
    if not match:
        return
    key = (name, match.group(0))
    if key not in seen:
        seen[key] = {
            "product": name,
            "version": match.group(0),
            "cpe": f"{SOFTWARE_CPE[name]}:{match.group(0)}",
            "header": header,
        }


def extract_software(*probes: dict) -> list[dict]:
    """Pull product/version pairs from disclosure headers and meta generator.

    A version is required; anything unmapped is skipped, never guessed.
    """
    seen: dict[tuple[str, str], dict] = {}
    for probe in probes:
        if not probe.get("ok"):
            continue
        headers = probe.get("headers", {})
        for header in ("server", "x-powered-by"):
            for token in headers.get(header, "").split():
                name, _, version = token.partition("/")
                name = name.lower()
                if name not in SOFTWARE_CPE:
                    continue
                match = _VERSION.match(version)
                if not match:
                    continue
                key = (name, match.group(0))
                if key not in seen:
                    seen[key] = {
                        "product": name,
                        "version": match.group(0),
                        "cpe": f"{SOFTWARE_CPE[name]}:{match.group(0)}",
                        "header": header,
                    }
        if headers.get("x-generator"):
            _add_generator(headers["x-generator"], "x-generator", seen)
        if probe.get("generator"):
            _add_generator(probe["generator"], "meta generator", seen)
    return list(seen.values())


def correlate_software(software: list[dict]) -> list[dict]:
    """Query the configured CVE sources for each disclosed product.

    Returns domain_findings-shaped dicts. Source failures are logged and
    skipped, exactly like local correlation: one dead source loses nothing.
    """
    sources = current_app.config["CVE_SOURCES"]
    merged: dict[str, dict] = {}
    evidence: dict[str, dict] = {}
    for item in software:
        try:
            normalized = cve.normalize_cpe(item["cpe"])
        except ValueError:
            continue
        for source in sources:
            try:
                if source == "nvd":
                    results = [{**result, "match_type": "exact"} for result in cve.lookup_cpe(normalized)]
                elif source == "circl":
                    results = circl.lookup_cpe(normalized, item["version"])
                else:
                    continue
            except (RuntimeError, circl.CirclError) as exc:
                current_app.logger.warning("Domain CVE source %s failed for %s: %s", source, normalized, exc)
                continue
            for result in results:
                cve_id = result["cve_id"]
                existing = merged.get(cve_id)
                if existing is None or cve._rank(result) > cve._rank(existing):
                    merged[cve_id] = result
                    evidence[cve_id] = item
    intel = exploit_intel.intel_for(list(merged))
    findings = []
    for cve_id, result in merged.items():
        item = evidence[cve_id]
        match_type = result.get("match_type", "exact")
        severity = SEVERITY_MAP.get(str(result.get("severity", "UNKNOWN")).upper(), "info")
        if match_type == "product":
            # Product-only leads are stored for review but never alert.
            severity = "info"
        detail = f"{result.get('summary', '')[:400]} Match confidence: {match_type} via {result.get('source', '')}."
        if intel.get(cve_id, {}).get("kev"):
            detail += " Listed in CISA KEV (known exploited)."
        if result.get("url"):
            detail += f" {result['url']}"
        findings.append(
            {
                "finding_key": f"cve.{cve_id}",
                "severity": severity,
                "category": "cve",
                "title": f"{cve_id} in {item['product']} {item['version']}",
                "detail": detail,
                "evidence": f"{item['header']}: {item['product']}/{item['version']}",
                "remediation": "Upgrade to a fixed version per the vendor advisory. Header versions can be masked or backported, so verify the actual package version.",
            }
        )
    return findings

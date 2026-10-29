"""Export formats for findings.

Findings are flattened once in `views/reports.py` and rendered here, so the CSV,
JSON, and SARIF outputs can never drift apart.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json

REPORT_FIELDS = [
    "type",
    "id",
    "severity",
    "score",
    "target",
    "port",
    "service",
    "match",
    "source",
    "kev",
    "epss",
    "title",
    "last_check",
    "first_seen",
    "last_seen",
    "url",
]

# SARIF levels: GitHub shows "error" prominently, so High and Critical map there.
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "note",
}


def to_csv(rows: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=REPORT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _fingerprint(row: dict) -> str:
    """Stable per-target identity so the same finding is not reopened on every export."""
    seed = f"{row['type']}|{row['id']}|{row['target']}|{row['port']}"
    return hashlib.sha256(seed.encode()).hexdigest()


def _rule(row: dict) -> dict:
    rule = {
        "id": str(row["id"]),
        "name": str(row["id"]),
        "shortDescription": {"text": (row["title"] or str(row["id"]))[:200]},
        "properties": {"severity": str(row["severity"]).lower(), "tags": [row["type"]]},
    }
    if row.get("score") is not None:
        # security-severity is what GitHub code scanning uses to bucket findings.
        rule["properties"]["security-severity"] = str(row["score"])
    if row.get("url"):
        rule["helpUri"] = row["url"]
    return rule


def _result(row: dict) -> dict:
    target = row["target"] or "unknown"
    where = f"{target}:{row['port']}" if row["port"] else target
    result = {
        "ruleId": str(row["id"]),
        "level": SARIF_LEVELS.get(str(row["severity"]).lower(), "note"),
        "message": {"text": f"{where} — {row['title'] or row['id']}"},
        "partialFingerprints": {"cvescout/v1": _fingerprint(row)},
        "properties": {
            "target": target,
            "port": row["port"],
            "service": row["service"],
            "severity": row["severity"],
            "score": row["score"],
            "match": row["match"],
            "source": row["source"],
            "knownExploited": bool(row["kev"]),
            "epss": row["epss"],
            "firstSeen": row.get("first_seen"),
            "lastSeen": row["last_seen"],
        },
    }
    if row.get("url"):
        result["helpUri"] = row["url"]
    return result


def to_sarif(rows: list[dict], tool_version: str, generated: str) -> dict:
    rules: dict[str, dict] = {}
    for row in rows:
        rules.setdefault(str(row["id"]), _rule(row))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CVE Scout",
                        "informationUri": "https://github.com/Dylpickle-Studios/cvescout",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(row) for row in rows],
                "invocations": [{"executionSuccessful": True, "endTimeUtc": generated}],
            }
        ],
    }


def to_json(rows: list[dict], generated: str) -> dict:
    return {"generated": generated, "count": len(rows), "findings": rows}


def dumps(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=False)

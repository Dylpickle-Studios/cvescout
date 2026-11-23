"""
System routes.
"""
from __future__ import annotations

import hmac
import os
from datetime import datetime
from pathlib import Path

from flask import (
    Response,
    abort,
    current_app,
    render_template,
    request,
)

from ..db import get_db
from ..version import __version__
from . import bp


@bp.get("/system")
def system():
    db = get_db()
    database = Path(current_app.config["DATABASE"])
    size_mb = round(os.path.getsize(database) / 1_048_576, 2) if database.exists() else 0
    profile = current_app.config["PROFILE"]
    counts = {
        table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("devices", "ports", "vulnerabilities", "domains", "domain_findings", "jobs", "events")
    }
    last_jobs = db.execute(
        "SELECT kind,MAX(finished_at) AS last FROM jobs WHERE status='completed' GROUP BY kind ORDER BY kind"
    ).fetchall()
    last_scan = db.execute("SELECT MAX(last_scanned) FROM domains").fetchone()[0]
    intel_rows = db.execute("SELECT COUNT(*),MAX(checked_at) FROM exploit_intel").fetchone()
    return render_template(
        "system.html",
        version=__version__,
        profile=profile,
        counts=counts,
        last_jobs=last_jobs,
        last_scan=last_scan,
        size_mb=size_mb,
        database=str(database),
        schema_version=db.execute("PRAGMA user_version").fetchone()[0],
        cve_sources=current_app.config["CVE_SOURCES"],
        retention=current_app.config["HISTORY_RETENTION_DAYS"],
        workers=current_app.config["WORKERS"],
        intel_rows=intel_rows[0],
        intel_checked=intel_rows[1],
        cloudflare=bool(current_app.config["CLOUDFLARE_API_TOKEN"]),
        nvd_key=bool(current_app.config["NVD_API_KEY"]),
        networks=current_app.config["NETWORKS"],
    )


@bp.get("/healthz")
def healthz():
    """Unauthenticated liveness probe; touches the database, reveals nothing else."""
    try:
        get_db().execute("SELECT 1")
    except Exception:  # noqa: BLE001 - any database failure means unhealthy.
        abort(503)
    return Response("ok\n", mimetype="text/plain")


def _metrics_body() -> str:
    db = get_db()
    devices = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online = db.execute("SELECT COUNT(*) FROM devices WHERE status='up'").fetchone()[0]
    ports = db.execute("SELECT COUNT(*) FROM ports WHERE state='open'").fetchone()[0]
    domains = db.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
    open_cves = db.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL AND acknowledged_at IS NULL"
    ).fetchone()[0]
    resolved = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NOT NULL").fetchone()[0]
    acknowledged = db.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL AND acknowledged_at IS NOT NULL"
    ).fetchone()[0]
    kev = db.execute("SELECT COUNT(*) FROM exploit_intel WHERE kev=1").fetchone()[0]
    schema = db.execute("PRAGMA user_version").fetchone()[0]
    lines = [
        "# HELP cvescout_build_info Build information.",
        "# TYPE cvescout_build_info gauge",
        f'cvescout_build_info{{version="{__version__}"}} 1',
        "# HELP cvescout_schema_version SQLite schema version.",
        "# TYPE cvescout_schema_version gauge",
        f"cvescout_schema_version {schema}",
        "# HELP cvescout_devices_total Known devices.",
        "# TYPE cvescout_devices_total gauge",
        f"cvescout_devices_total {devices}",
        "# HELP cvescout_devices_online Devices seen up in the last discovery.",
        "# TYPE cvescout_devices_online gauge",
        f"cvescout_devices_online {online}",
        "# HELP cvescout_ports_open_total Open ports in the inventory.",
        "# TYPE cvescout_ports_open_total gauge",
        f"cvescout_ports_open_total {ports}",
        "# HELP cvescout_domains_total Configured public hostnames.",
        "# TYPE cvescout_domains_total gauge",
        f"cvescout_domains_total {domains}",
        "# HELP cvescout_vulnerabilities CVE findings by state.",
        "# TYPE cvescout_vulnerabilities gauge",
        f'cvescout_vulnerabilities{{state="open"}} {open_cves}',
        f'cvescout_vulnerabilities{{state="resolved"}} {resolved}',
        f'cvescout_vulnerabilities{{state="acknowledged"}} {acknowledged}',
        "# HELP cvescout_vulnerabilities_open_severity Open CVE findings by severity.",
        "# TYPE cvescout_vulnerabilities_open_severity gauge",
    ]
    for row in db.execute(
        "SELECT severity,COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL AND acknowledged_at IS NULL GROUP BY severity"
    ):
        lines.append(f'cvescout_vulnerabilities_open_severity{{severity="{row[0]}"}} {row[1]}')
    lines += [
        "# HELP cvescout_domain_findings_open Open public hostname findings by severity.",
        "# TYPE cvescout_domain_findings_open gauge",
    ]
    for row in db.execute(
        "SELECT severity,COUNT(*) FROM domain_findings WHERE resolved_at IS NULL AND acknowledged_at IS NULL "
        "AND severity!='info' GROUP BY severity"
    ):
        lines.append(f'cvescout_domain_findings_open{{severity="{row[0]}"}} {row[1]}')
    lines += [
        "# HELP cvescout_kev_entries CVEs in the local KEV catalogue.",
        "# TYPE cvescout_kev_entries gauge",
        f"cvescout_kev_entries {kev}",
        "# HELP cvescout_job_last_success_timestamp_seconds Unix time of the last completed job per kind.",
        "# TYPE cvescout_job_last_success_timestamp_seconds gauge",
    ]
    for row in db.execute("SELECT kind,MAX(finished_at) FROM jobs WHERE status='completed' GROUP BY kind"):
        try:
            stamp = datetime.fromisoformat(row[1]).timestamp()
        except (TypeError, ValueError):
            continue
        lines.append(f'cvescout_job_last_success_timestamp_seconds{{kind="{row[0]}"}} {stamp:.0f}')
    return "\n".join(lines) + "\n"


@bp.get("/metrics")
def metrics():
    """Prometheus text metrics. Disabled unless CVESCOUT_METRICS_TOKEN is set;
    then a matching bearer token is required, so counts never leak by default."""
    token = current_app.config["METRICS_TOKEN"]
    if not token:
        abort(404)
    supplied = request.headers.get("Authorization", "").encode()
    if not hmac.compare_digest(supplied, f"Bearer {token}".encode()):
        abort(401)
    return Response(_metrics_body(), mimetype="text/plain; version=0.0.4; charset=utf-8")

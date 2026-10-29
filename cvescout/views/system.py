"""
System routes.
"""
from __future__ import annotations

import os
from pathlib import Path

from flask import (
    current_app,
    render_template,
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

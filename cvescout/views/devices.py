"""
Devices routes.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .. import exporters
from ..checks import CHECKS, RESULT_LABELS
from ..db import get_db, log_event, now
from ..jobs import (
    JobBusy,
    submit_check,
    submit_scan,
)
from . import PAGE_SIZE, _active_jobs, bp, download, paginate


def _finding_trend(days: int = 30) -> dict:
    """Daily new vs resolved CVE findings, shaped for a server-rendered SVG."""
    db = get_db()
    start = datetime.now(UTC).date() - timedelta(days=days - 1)
    cutoff = start.isoformat()
    new_counts = {
        row["day"]: row["count"]
        for row in db.execute(
            "SELECT substr(first_seen,1,10) AS day,COUNT(*) AS count FROM vulnerabilities "
            "WHERE first_seen >= ? GROUP BY day",
            (cutoff,),
        )
    }
    resolved_counts = {
        row["day"]: row["count"]
        for row in db.execute(
            "SELECT substr(resolved_at,1,10) AS day,COUNT(*) AS count FROM vulnerabilities "
            "WHERE resolved_at >= ? GROUP BY day",
            (cutoff,),
        )
    }
    labels = [(start + timedelta(days=i)).isoformat() for i in range(days)]
    new = [new_counts.get(day, 0) for day in labels]
    resolved = [resolved_counts.get(day, 0) for day in labels]
    peak = max(1, max(new), max(resolved))
    width, height, pad = 600, 140, 12
    step = (width - 2 * pad) / (days - 1)

    def points(series: list[int]) -> str:
        return " ".join(
            f"{pad + i * step:.1f},{height - pad - (value / peak) * (height - 2 * pad):.1f}"
            for i, value in enumerate(series)
        )

    return {
        "new_points": points(new),
        "resolved_points": points(resolved),
        "peak": peak,
        "start": labels[0],
        "end": labels[-1],
        "new_total": sum(new),
        "resolved_total": sum(resolved),
        "width": width,
        "height": height,
    }


@bp.get("/")
def dashboard():
    db = get_db()
    counts = {
        "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "online": db.execute("SELECT COUNT(*) FROM devices WHERE status='up'").fetchone()[0],
        "ports": db.execute("SELECT COUNT(*) FROM ports WHERE state='open'").fetchone()[0],
        "vulnerabilities": db.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL AND acknowledged_at IS NULL"
        ).fetchone()[0],
        "resolved": db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NOT NULL").fetchone()[0],
        "acknowledged": db.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL AND acknowledged_at IS NOT NULL"
        ).fetchone()[0],
        "domains": db.execute("SELECT COUNT(*) FROM domains").fetchone()[0],
        "external_findings": db.execute(
            "SELECT COUNT(*) FROM domain_findings WHERE severity!='info' AND resolved_at IS NULL AND acknowledged_at IS NULL"
        ).fetchone()[0],
    }
    devices = db.execute(
        "SELECT d.*,COUNT(DISTINCT p.id) AS port_count,COUNT(DISTINCT v.id) AS vulnerability_count "
        "FROM devices d LEFT JOIN ports p ON p.device_id=d.id "
        "LEFT JOIN vulnerabilities v ON v.port_id=p.id AND v.resolved_at IS NULL AND v.acknowledged_at IS NULL "
        "GROUP BY d.id ORDER BY d.status DESC,d.address"
    ).fetchall()
    jobs = db.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 12").fetchall()
    events = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 20").fetchall()
    return render_template(
        "dashboard.html",
        counts=counts,
        devices=devices,
        jobs=jobs,
        events=events,
        networks=current_app.config["NETWORKS"],
        active_jobs=_active_jobs(),
        trend=_finding_trend(),
    )

def _device_findings(device_id: int) -> tuple[dict, list[dict]]:
    """Rows for one device, shaped exactly like the report export rows."""
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not device:
        return {}, []
    rows = db.execute(
        "SELECT v.cve_id,v.severity,v.score,v.summary,v.url,v.last_seen,v.first_seen,v.source,v.match_type,"
        "COALESCE(i.kev,0) AS kev,i.epss AS epss,"
        "p.port,p.protocol,p.service,p.product,p.version,"
        "(SELECT result FROM checks c WHERE c.vulnerability_id=v.id ORDER BY c.id DESC LIMIT 1) AS check_result "
        "FROM vulnerabilities v JOIN ports p ON p.id=v.port_id "
        "LEFT JOIN exploit_intel i ON i.cve_id=v.cve_id WHERE p.device_id=? AND v.resolved_at IS NULL AND v.acknowledged_at IS NULL "
        "ORDER BY COALESCE(i.kev,0) DESC,COALESCE(i.epss,0) DESC,COALESCE(v.score,0) DESC,v.cve_id",
        (device_id,),
    ).fetchall()
    findings = [
        {
            "type": "cve",
            "id": item["cve_id"],
            "severity": item["severity"],
            "score": item["score"],
            "target": device["hostname"] or device["address"],
            "port": f"{item['port']}/{item['protocol']}",
            "service": f"{item['product']} {item['version']}".strip() or item["service"],
            "match": item["match_type"],
            "source": item["source"],
            "kev": bool(item["kev"]),
            "epss": item["epss"],
            "title": item["summary"],
            "last_check": item["check_result"] or "not checked",
            "first_seen": item["first_seen"] or item["last_seen"],
            "last_seen": item["last_seen"],
            "url": item["url"],
        }
        for item in rows
    ]
    return dict(device), findings


@bp.get("/devices/<int:device_id>.json")
def device_json(device_id: int):
    device, findings = _device_findings(device_id)
    if not device:
        return ("Device not found", 404)
    document = exporters.to_json(findings, now())
    document["device"] = {"address": device["address"], "hostname": device["hostname"], "status": device["status"]}
    return download(exporters.dumps(document), "application/json", f"{device['address']}.json")


@bp.get("/devices/<int:device_id>.csv")
def device_csv(device_id: int):
    device, findings = _device_findings(device_id)
    if not device:
        return ("Device not found", 404)
    return download(exporters.to_csv(findings), "text/csv", f"{device['address']}.csv")


@bp.get("/devices/<int:device_id>")
def device(device_id: int):
    db = get_db()
    item = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not item:
        return ("Device not found", 404)
    ports = db.execute(
        "SELECT p.*,COUNT(v.id) AS vulnerability_count FROM ports p "
        "LEFT JOIN vulnerabilities v ON v.port_id=p.id AND v.resolved_at IS NULL AND v.acknowledged_at IS NULL "
        "WHERE p.device_id=? GROUP BY p.id ORDER BY p.port,p.protocol",
        (device_id,),
    ).fetchall()
    order = (
        "ORDER BY COALESCE(i.kev,0) DESC,COALESCE(i.epss,0) DESC,COALESCE(v.score,0) DESC,v.cve_id"
    )
    where = (
        "FROM vulnerabilities v JOIN ports p ON p.id=v.port_id LEFT JOIN exploit_intel i ON i.cve_id=v.cve_id "
        "WHERE p.device_id=? AND v.resolved_at IS NULL AND v.acknowledged_at IS NULL"
    )
    total = db.execute(f"SELECT COUNT(*) {where}", (device_id,)).fetchone()[0]
    page, pages, offset = paginate(total)
    vulnerabilities = db.execute(
        "SELECT v.*,p.port,p.protocol,p.service,p.product,p.version,"
        "COALESCE(i.kev,0) AS kev,i.epss AS epss,"
        "(SELECT result FROM checks c WHERE c.vulnerability_id=v.id ORDER BY c.id DESC LIMIT 1) AS check_result,"
        "(SELECT details FROM checks c WHERE c.vulnerability_id=v.id ORDER BY c.id DESC LIMIT 1) AS check_details "
        f"{where} {order} LIMIT ? OFFSET ?",
        (device_id, PAGE_SIZE, offset),
    ).fetchall()
    acknowledged = db.execute(
        "SELECT v.*,p.port,p.protocol FROM vulnerabilities v JOIN ports p ON p.id=v.port_id "
        "WHERE p.device_id=? AND v.resolved_at IS NULL AND v.acknowledged_at IS NOT NULL ORDER BY v.cve_id",
        (device_id,),
    ).fetchall()
    return render_template(
        "device.html",
        device=item,
        ports=ports,
        vulnerabilities=vulnerabilities,
        acknowledged=acknowledged,
        checks_info=CHECKS,
        result_labels=RESULT_LABELS,
        active_jobs=_active_jobs(),
        page=page,
        pages=pages,
        total=total,
    )

@bp.post("/scans/<kind>")
def scan(kind: str):
    if kind not in {"network", "devices", "ports", "vulnerabilities"}:
        return ("Unknown scan type", 404)
    raw_device_id = request.form.get("device_id", "").strip()
    try:
        device_id = int(raw_device_id) if raw_device_id else None
    except ValueError:
        return ("Invalid device", 400)
    if kind in {"network", "devices"}:
        device_id = None
    try:
        job_id = submit_scan(current_app._get_current_object(), kind, device_id, session["user"])  # type: ignore[attr-defined]
    except JobBusy as exc:
        flash(f"{kind.title()} scan not queued: {exc}", "error")
        return redirect(request.referrer or url_for("main.dashboard"))
    flash(f"{kind.title()} scan queued as job {job_id}", "success")
    return redirect(request.referrer or url_for("main.dashboard"))

@bp.post("/vulnerabilities/<int:vulnerability_id>/check")
def check_vulnerability(vulnerability_id: int):
    try:
        job_id, _check_id = submit_check(current_app._get_current_object(), vulnerability_id, session["user"])  # type: ignore[attr-defined]
    except ValueError as exc:
        return (str(exc), 404)
    except JobBusy as exc:
        flash(f"Check not queued: {exc}", "error")
        return redirect(request.referrer or url_for("main.dashboard"))
    flash(f"Vulnerability check queued as job {job_id}", "success")
    return redirect(request.referrer or url_for("main.dashboard"))


@bp.post("/vulnerabilities/<int:vulnerability_id>/acknowledge")
def acknowledge_vulnerability(vulnerability_id: int):
    db = get_db()
    row = db.execute(
        "SELECT v.cve_id,p.device_id FROM vulnerabilities v JOIN ports p ON p.id=v.port_id WHERE v.id=?",
        (vulnerability_id,),
    ).fetchone()
    if not row:
        return ("Vulnerability not found", 404)
    note = request.form.get("note", "").strip()[:500]
    db.execute(
        "UPDATE vulnerabilities SET acknowledged_at=?,acknowledged_by=?,acknowledge_note=? WHERE id=?",
        (now(), session["user"], note, vulnerability_id),
    )
    db.commit()
    message = f"Acknowledged {row['cve_id']}" + (f": {note}" if note else "")
    log_event("info", "vulnerability.acknowledge", message, str(vulnerability_id), session["user"])
    flash(f"Acknowledged {row['cve_id']}; it is hidden from current reports and alerts", "success")
    return redirect(request.referrer or url_for("main.device", device_id=row["device_id"]))


@bp.post("/vulnerabilities/<int:vulnerability_id>/unacknowledge")
def unacknowledge_vulnerability(vulnerability_id: int):
    db = get_db()
    row = db.execute(
        "SELECT v.cve_id,p.device_id FROM vulnerabilities v JOIN ports p ON p.id=v.port_id WHERE v.id=?",
        (vulnerability_id,),
    ).fetchone()
    if not row:
        return ("Vulnerability not found", 404)
    db.execute(
        "UPDATE vulnerabilities SET acknowledged_at=NULL,acknowledged_by='',acknowledge_note='' WHERE id=?",
        (vulnerability_id,),
    )
    db.commit()
    log_event("info", "vulnerability.unacknowledge", f"Acknowledgment removed for {row['cve_id']}", str(vulnerability_id), session["user"])
    flash(f"Acknowledgment removed for {row['cve_id']}", "success")
    return redirect(request.referrer or url_for("main.device", device_id=row["device_id"]))

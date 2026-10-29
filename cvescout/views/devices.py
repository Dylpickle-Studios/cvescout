"""
Devices routes.
"""
from __future__ import annotations

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
from ..checks import SAFE_NSE_CHECKS
from ..db import get_db, now
from ..jobs import (
    JobBusy,
    submit_check,
    submit_scan,
)
from . import PAGE_SIZE, _active_jobs, bp, download, paginate


@bp.get("/")
def dashboard():
    db = get_db()
    counts = {
        "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "online": db.execute("SELECT COUNT(*) FROM devices WHERE status='up'").fetchone()[0],
        "ports": db.execute("SELECT COUNT(*) FROM ports WHERE state='open'").fetchone()[0],
        "vulnerabilities": db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL").fetchone()[0],
        "resolved": db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NOT NULL").fetchone()[0],
        "domains": db.execute("SELECT COUNT(*) FROM domains").fetchone()[0],
        "external_findings": db.execute(
            "SELECT COUNT(*) FROM domain_findings WHERE severity!='info' AND resolved_at IS NULL"
        ).fetchone()[0],
    }
    devices = db.execute(
        "SELECT d.*,COUNT(DISTINCT p.id) AS port_count,COUNT(DISTINCT v.id) AS vulnerability_count "
        "FROM devices d LEFT JOIN ports p ON p.device_id=d.id LEFT JOIN vulnerabilities v ON v.port_id=p.id "
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
        "LEFT JOIN exploit_intel i ON i.cve_id=v.cve_id WHERE p.device_id=? AND v.resolved_at IS NULL "
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
        "SELECT p.*,COUNT(v.id) AS vulnerability_count FROM ports p LEFT JOIN vulnerabilities v ON v.port_id=p.id "
        "WHERE p.device_id=? GROUP BY p.id ORDER BY p.port,p.protocol",
        (device_id,),
    ).fetchall()
    order = (
        "ORDER BY COALESCE(i.kev,0) DESC,COALESCE(i.epss,0) DESC,COALESCE(v.score,0) DESC,v.cve_id"
    )
    where = (
        "FROM vulnerabilities v JOIN ports p ON p.id=v.port_id LEFT JOIN exploit_intel i ON i.cve_id=v.cve_id "
        "WHERE p.device_id=? AND v.resolved_at IS NULL"
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
    return render_template(
        "device.html",
        device=item,
        ports=ports,
        vulnerabilities=vulnerabilities,
        safe_checks=SAFE_NSE_CHECKS,
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
        job_id = submit_scan(current_app._get_current_object(), kind, device_id, session["user"])
    except JobBusy as exc:
        flash(f"{kind.title()} scan not queued: {exc}", "error")
        return redirect(request.referrer or url_for("main.dashboard"))
    flash(f"{kind.title()} scan queued as job {job_id}", "success")
    return redirect(request.referrer or url_for("main.dashboard"))

@bp.post("/vulnerabilities/<int:vulnerability_id>/check")
def check_vulnerability(vulnerability_id: int):
    try:
        job_id, _check_id = submit_check(current_app._get_current_object(), vulnerability_id, session["user"])
    except ValueError as exc:
        return (str(exc), 404)
    except JobBusy as exc:
        flash(f"Check not queued: {exc}", "error")
        return redirect(request.referrer or url_for("main.dashboard"))
    flash(f"Vulnerability check queued as job {job_id}", "success")
    return redirect(request.referrer or url_for("main.dashboard"))

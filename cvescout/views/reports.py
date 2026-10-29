"""
Reports routes.
"""
from __future__ import annotations

from flask import jsonify, render_template, request

from .. import exporters
from ..db import get_db, now
from ..version import __version__
from . import PAGE_SIZE, bp, download, paginate

VULN_SELECT = (
    "SELECT v.*,d.id AS device_id,d.address,d.hostname,p.port,p.protocol,p.service,p.product,p.version,"
    "COALESCE(i.kev,0) AS kev,i.epss AS epss,"
    "(SELECT result FROM checks c WHERE c.vulnerability_id=v.id ORDER BY c.id DESC LIMIT 1) AS check_result "
    "FROM vulnerabilities v JOIN ports p ON p.id=v.port_id JOIN devices d ON d.id=p.device_id "
    "LEFT JOIN exploit_intel i ON i.cve_id=v.cve_id WHERE v.resolved_at IS NULL "
    "ORDER BY COALESCE(i.kev,0) DESC,COALESCE(i.epss,0) DESC,COALESCE(v.score,0) DESC,v.cve_id"
)


@bp.get("/reports")
def reports():
    total = get_db().execute("SELECT COUNT(*) FROM vulnerabilities WHERE resolved_at IS NULL").fetchone()[0]
    page, pages, offset = paginate(total)
    severity, vulnerabilities, domain_findings, checks, domain_checks = _report_rows(PAGE_SIZE, offset)
    return render_template(
        "reports.html",
        severity=severity,
        vulnerabilities=vulnerabilities,
        checks=checks,
        domain_findings=domain_findings,
        domain_checks=domain_checks,
        page=page,
        pages=pages,
        total=total,
        page_size=PAGE_SIZE,
    )

def _report_rows(limit: int | None = None, offset: int = 0):
    db = get_db()
    severity = db.execute(
        "SELECT severity,COUNT(*) AS count FROM vulnerabilities WHERE resolved_at IS NULL "
        "GROUP BY severity ORDER BY count DESC"
    ).fetchall()
    sql = VULN_SELECT + (" LIMIT ? OFFSET ?" if limit else "")
    vulnerabilities = db.execute(sql, (limit, offset) if limit else ()).fetchall()
    checks = db.execute(
        "SELECT c.*,v.cve_id,d.address,p.port FROM checks c JOIN vulnerabilities v ON v.id=c.vulnerability_id "
        "JOIN ports p ON p.id=v.port_id JOIN devices d ON d.id=p.device_id ORDER BY c.id DESC LIMIT 100"
    ).fetchall()
    domain_findings = db.execute(
        "SELECT f.*,d.id AS domain_id,d.name,d.provider FROM domain_findings f "
        "JOIN domains d ON d.id=f.domain_id WHERE f.severity!='info' AND f.resolved_at IS NULL ORDER BY "
        "CASE f.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,d.name,f.title"
    ).fetchall()
    domain_checks = db.execute(
        "SELECT c.*,d.id AS domain_id,d.name FROM domain_checks c "
        "JOIN domains d ON d.id=c.domain_id ORDER BY c.id DESC LIMIT 100"
    ).fetchall()
    return severity, vulnerabilities, domain_findings, checks, domain_checks

def _report_findings() -> list[dict]:
    """One flat list of every current finding, shared by the CSV and JSON exports."""
    _severity, vulnerabilities, domain_findings, _checks, _domain_checks = _report_rows()
    rows = [
        {
            "type": "cve",
            "id": item["cve_id"],
            "severity": item["severity"],
            "score": item["score"],
            "target": item["hostname"] or item["address"],
            "port": f"{item['port']}/{item['protocol']}",
            "service": f"{item['product']} {item['version']}".strip() or item["service"],
            "title": item["summary"],
            "last_check": item["check_result"] or "not checked",
            "first_seen": item["first_seen"] or item["last_seen"],
            "last_seen": item["last_seen"],
            "url": item["url"],
            "match": item["match_type"],
            "source": item["source"],
            "kev": bool(item["kev"]),
            "epss": item["epss"],
        }
        for item in vulnerabilities
    ]
    rows += [
        {
            "type": "domain",
            "id": item["finding_key"],
            "severity": item["severity"],
            "score": None,
            "target": item["name"],
            "port": "",
            "service": item["category"],
            "title": item["title"],
            "last_check": f"via {item['provider']}" if item["provider"] else "",
            "first_seen": item["first_seen"] or item["last_seen"],
            "last_seen": item["last_seen"],
            "url": "",
            "match": "config",
            "source": "domain",
            "kev": False,
            "epss": None,
        }
        for item in domain_findings
    ]
    return rows

@bp.get("/reports.csv")
def reports_csv():
    return download(exporters.to_csv(_report_findings()), "text/csv", "reports.csv")


@bp.get("/reports.json")
def reports_json():
    return jsonify(exporters.to_json(_report_findings(), now()))


@bp.get("/reports.sarif")
def reports_sarif():
    document = exporters.to_sarif(_report_findings(), __version__, now())
    return download(exporters.dumps(document), "application/sarif+json", "reports.sarif")

@bp.get("/logs")
def logs():
    db = get_db()
    level = request.args.get("level", "").strip().lower()
    where, params = ("WHERE level=?", (level,)) if level else ("", ())
    total = db.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
    page, pages, offset = paginate(total)
    events = db.execute(
        f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, PAGE_SIZE, offset),
    ).fetchall()
    levels = [row[0] for row in db.execute("SELECT DISTINCT level FROM events ORDER BY level")]
    return render_template(
        "logs.html",
        events=events,
        page=page,
        pages=pages,
        total=total,
        level=level,
        levels=levels,
    )

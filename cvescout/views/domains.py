"""
Domains routes.
"""
from __future__ import annotations

import json

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..cloudflare_checks import CloudflareCheckError
from ..db import get_db, log_event, now
from ..domain_scanner import DomainScanError, normalize_domain
from ..jobs import (
    JobBusy,
    submit_cloudflare_check,
    submit_domain_scan,
    submit_origin_check,
)
from ..provider_checks import ProviderCheckError
from . import _active_jobs, bp


@bp.route("/domains", methods=("GET", "POST"))
def domains():
    db = get_db()
    if request.method == "POST":
        if request.form.get("authorized") != "yes":
            flash("Confirm authorization before adding a public hostname", "error")
            return redirect(url_for("main.domains"))
        try:
            name = normalize_domain(request.form.get("name", ""))
        except DomainScanError as exc:
            flash(str(exc), "error")
            return redirect(url_for("main.domains"))
        cursor = db.execute(
            "INSERT OR IGNORE INTO domains(name,created_at) VALUES(?,?)",
            (name, now()),
        )
        db.commit()
        if cursor.rowcount:
            log_event("info", "domain.add", "Public hostname added", name, session["user"])
            flash(f"Added {name}", "success")
        else:
            flash(f"{name} is already configured", "error")
        return redirect(url_for("main.domains"))
    items = db.execute(
        "SELECT d.*,COUNT(f.id) AS finding_count,"
        "SUM(CASE WHEN f.severity='high' THEN 1 ELSE 0 END) AS high_count,"
        "SUM(CASE WHEN f.severity='medium' THEN 1 ELSE 0 END) AS medium_count "
        "FROM domains d LEFT JOIN domain_findings f ON f.domain_id=d.id AND f.resolved_at IS NULL AND f.acknowledged_at IS NULL "
        "GROUP BY d.id ORDER BY d.name"
    ).fetchall()
    return render_template("domains.html", domains=items, active_jobs=_active_jobs())

@bp.get("/domains/<int:domain_id>")
def domain(domain_id: int):
    db = get_db()
    item = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not item:
        return ("Domain not found", 404)
    findings = db.execute(
        "SELECT * FROM domain_findings WHERE domain_id=? AND resolved_at IS NULL AND acknowledged_at IS NULL ORDER BY "
        "CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,category,title",
        (domain_id,),
    ).fetchall()
    acknowledged = db.execute(
        "SELECT * FROM domain_findings WHERE domain_id=? AND resolved_at IS NULL AND acknowledged_at IS NOT NULL ORDER BY title",
        (domain_id,),
    ).fetchall()
    summaries = {
        "addresses": json.loads(item["addresses"]),
        "dns": json.loads(item["dns_summary"]),
        "tls": json.loads(item["tls_summary"]),
        "http": json.loads(item["http_summary"]),
    }
    checks = []
    for row in db.execute("SELECT * FROM domain_checks WHERE domain_id=? ORDER BY id DESC LIMIT 50", (domain_id,)):
        check = dict(row)
        check["details"] = json.loads(check["details"])
        checks.append(check)
    return render_template(
        "domain.html",
        domain=item,
        findings=findings,
        acknowledged=acknowledged,
        summaries=summaries,
        checks=checks,
        cloudflare_configured=bool(current_app.config["CLOUDFLARE_API_TOKEN"]),
        active_jobs=_active_jobs(item["name"]),
    )

@bp.post("/domains/<int:domain_id>/scan")
def scan_domain(domain_id: int):
    try:
        job_id = submit_domain_scan(current_app._get_current_object(), domain_id, session["user"])  # type: ignore[attr-defined]
    except ValueError as exc:
        return (str(exc), 404)
    except JobBusy as exc:
        flash(f"Domain scan not queued: {exc}", "error")
        return redirect(url_for("main.domain", domain_id=domain_id))
    flash(f"Public domain scan queued as job {job_id}", "success")
    return redirect(request.referrer or url_for("main.domains"))

@bp.post("/domains/scan-all")
def scan_all_domains():
    rows = get_db().execute("SELECT id FROM domains ORDER BY name").fetchall()
    queued = 0
    for row in rows:
        try:
            submit_domain_scan(current_app._get_current_object(), row["id"], session["user"])  # type: ignore[attr-defined]
            queued += 1
        except JobBusy:
            continue
    flash(f"Queued {queued} public domain scans; {len(rows) - queued} already in progress", "success")
    return redirect(url_for("main.domains"))

@bp.post("/domains/<int:domain_id>/check-origin")
def check_domain_origin(domain_id: int):
    if request.form.get("authorized") != "yes":
        flash("Confirm authorization before checking an origin IP", "error")
        return redirect(url_for("main.domain", domain_id=domain_id))
    try:
        job_id, _check_id = submit_origin_check(
            current_app._get_current_object(),  # type: ignore[attr-defined]
            domain_id,
            request.form.get("origin_ip", ""),
            session["user"],
        )
    except (ProviderCheckError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.domain", domain_id=domain_id))
    except JobBusy as exc:
        flash(f"Origin check not queued: {exc}", "error")
        return redirect(url_for("main.domain", domain_id=domain_id))
    flash(f"Origin reachability check queued as job {job_id}", "success")
    return redirect(url_for("main.domain", domain_id=domain_id))

@bp.post("/domains/<int:domain_id>/check-cloudflare")
def check_domain_cloudflare(domain_id: int):
    try:
        job_id, _check_id = submit_cloudflare_check(
            current_app._get_current_object(), domain_id, session["user"]  # type: ignore[attr-defined]
        )
    except (CloudflareCheckError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.domain", domain_id=domain_id))
    except JobBusy as exc:
        flash(f"Cloudflare check not queued: {exc}", "error")
        return redirect(url_for("main.domain", domain_id=domain_id))
    flash(f"Cloudflare configuration check queued as job {job_id}", "success")
    return redirect(url_for("main.domain", domain_id=domain_id))

@bp.post("/domains/<int:domain_id>/delete")
def delete_domain(domain_id: int):
    db = get_db()
    item = db.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not item:
        return ("Domain not found", 404)
    db.execute("DELETE FROM domains WHERE id=?", (domain_id,))
    db.commit()
    log_event("info", "domain.delete", "Public hostname removed", item["name"], session["user"])
    flash(f"Removed {item['name']}", "success")
    return redirect(url_for("main.domains"))


@bp.post("/domain-findings/<int:finding_id>/acknowledge")
def acknowledge_domain_finding(finding_id: int):
    db = get_db()
    row = db.execute("SELECT domain_id,title FROM domain_findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        return ("Finding not found", 404)
    note = request.form.get("note", "").strip()[:500]
    db.execute(
        "UPDATE domain_findings SET acknowledged_at=?,acknowledged_by=?,acknowledge_note=? WHERE id=?",
        (now(), session["user"], note, finding_id),
    )
    db.commit()
    message = f"Acknowledged {row['title']}" + (f": {note}" if note else "")
    log_event("info", "domain_finding.acknowledge", message, str(finding_id), session["user"])
    flash(f"Acknowledged: {row['title']}", "success")
    return redirect(request.referrer or url_for("main.domain", domain_id=row["domain_id"]))


@bp.post("/domain-findings/<int:finding_id>/unacknowledge")
def unacknowledge_domain_finding(finding_id: int):
    db = get_db()
    row = db.execute("SELECT domain_id,title FROM domain_findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        return ("Finding not found", 404)
    db.execute(
        "UPDATE domain_findings SET acknowledged_at=NULL,acknowledged_by='',acknowledge_note='' WHERE id=?",
        (finding_id,),
    )
    db.commit()
    log_event("info", "domain_finding.unacknowledge", f"Acknowledgment removed for {row['title']}", str(finding_id), session["user"])
    flash(f"Acknowledgment removed for {row['title']}", "success")
    return redirect(request.referrer or url_for("main.domain", domain_id=row["domain_id"]))

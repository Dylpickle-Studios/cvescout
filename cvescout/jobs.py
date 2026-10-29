from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from flask import current_app

from . import (
    checks,
    cloudflare_checks,
    cve,
    domain_scanner,
    notify,
    provider_checks,
    scanner,
)
from .db import get_db, log_event, now

_executor: ThreadPoolExecutor | None = None


def _pool() -> ThreadPoolExecutor:
    """One pool per process, sized by the detected profile (1 worker on a Pi Zero)."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(
            max_workers=max(1, current_app.config["WORKERS"]),
            thread_name_prefix="cvescout",
        )
    return _executor


def _redact(text: str, *secrets: str) -> str:
    """Keep failure text debuggable without persisting supplied origin IPs."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<origin>")
    return text


class JobBusy(RuntimeError):
    """Raised when identical work is already queued or running."""


def _ensure_idle(db, kind: str, target: str) -> None:
    row = db.execute(
        "SELECT id FROM jobs WHERE kind=? AND target=? AND status IN ('queued','running') ORDER BY id DESC LIMIT 1",
        (kind, target),
    ).fetchone()
    if row:
        raise JobBusy(f"Already queued as job {row['id']}; wait for it to finish")


def _notify_failure(job_id: int, message: str) -> None:
    try:
        row = get_db().execute("SELECT kind,target FROM jobs WHERE id=?", (job_id,)).fetchone()
        kind = row["kind"] if row else "job"
        where = f" for {row['target']}" if row and row["target"] else ""
        notify.notify(f"CVE Scout {kind} failed", f"Job {job_id}{where}: {message}", "high")
    except Exception:  # noqa: BLE001 - a notification must never hide the recorded failure.
        current_app.logger.warning("Failure notification for job %s was not delivered", job_id)


def _set_job(job_id: int, status: str, message: str = "") -> None:
    db = get_db()
    fields = "status=?,message=?"
    values: list = [status, message]
    if status == "running":
        fields += ",started_at=?"
        values.append(now())
    if status in {"completed", "failed"}:
        fields += ",finished_at=?"
        values.append(now())
    values.append(job_id)
    db.execute(f"UPDATE jobs SET {fields} WHERE id=?", values)
    db.commit()
    if status == "failed":
        _notify_failure(job_id, message)


def _insert_job(kind: str, target: str, username: str) -> int:
    db = get_db()
    job_id = db.execute(
        "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
        (kind, target, username, "queued", now()),
    ).lastrowid
    db.commit()
    return job_id


def run_scan_now(
    kind: str,
    device_id: int | None,
    username: str,
    domain_id: int | None = None,
) -> tuple[str, str]:
    """Run one scan synchronously and record it as a job. Used by the CLI, not the web UI."""
    app = current_app._get_current_object()
    db = get_db()
    if domain_id is not None:
        domain = db.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
        if not domain:
            raise ValueError("Domain not found")
        kind, target = "domain", domain["name"]
    else:
        target = str(device_id or "")
    job_id = _insert_job(kind, target, username)
    if domain_id is not None:
        _run_domain_scan(app, job_id, domain_id, username)
    else:
        _run_scan(app, job_id, kind, device_id, username)
    row = db.execute("SELECT status,message FROM jobs WHERE id=?", (job_id,)).fetchone()
    return row["status"], row["message"]


def _run_scan(app, job_id: int, kind: str, device_id: int | None, username: str) -> None:
    with app.app_context():
        _set_job(job_id, "running")
        try:
            if kind == "network":
                count = scanner.discover_network()
                message = f"Discovered {count} online devices"
            elif kind == "devices":
                count = scanner.refresh_devices()
                message = f"Refreshed devices; {count} online"
            elif kind == "ports":
                devices, ports = scanner.scan_all_ports(device_id)
                message = f"Scanned {devices} devices; found {ports} open ports"
            elif kind == "vulnerabilities":
                ports, vulnerabilities, new_cves = cve.correlate_all(device_id)
                message = f"Profiled {ports} ports; matched {vulnerabilities} CVEs"
                if new_cves:
                    notify.notify(
                        f"New CVE matches on {device_id or 'the network'}",
                        "\n".join(new_cves[:10]),
                        "high",
                    )
            else:
                raise ValueError("Unknown scan type")
            _set_job(job_id, "completed", message)
            log_event("info", f"scan.{kind}", message, str(device_id or "all"), username)
        except Exception as exc:  # noqa: BLE001 - job failures must always be recorded.
            message = str(exc)
            _set_job(job_id, "failed", message)
            log_event("error", f"scan.{kind}", message, str(device_id or "all"), username)


def submit_scan(app, kind: str, device_id: int | None, username: str) -> int:
    db = get_db()
    target = str(device_id or "")
    _ensure_idle(db, kind, target)
    job_id = _insert_job(kind, target, username)
    log_event("info", f"scan.{kind}.queued", "Scan queued", str(device_id or "all"), username)
    _pool().submit(_run_scan, app, job_id, kind, device_id, username)
    return job_id


def _run_domain_scan(app, job_id: int, domain_id: int, username: str) -> None:
    with app.app_context():
        _set_job(job_id, "running")
        db = get_db()
        domain = db.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
        try:
            if not domain:
                raise ValueError("Domain not found")
            findings, new_findings = domain_scanner.scan_domain(domain_id)
            message = f"Scanned {domain['name']}; recorded {findings} findings"
            if new_findings:
                notify.notify(
                    f"New exposure finding on {domain['name']}",
                    "\n".join(new_findings[:10]),
                    "high",
                )
            _set_job(job_id, "completed", message)
            log_event("info", "scan.domain", message, domain["name"], username)
        except Exception as exc:  # noqa: BLE001 - job failures must always be recorded.
            message = str(exc)
            _set_job(job_id, "failed", message)
            log_event("error", "scan.domain", message, domain["name"] if domain else str(domain_id), username)


def submit_domain_scan(app, domain_id: int, username: str) -> int:
    db = get_db()
    domain = db.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not domain:
        raise ValueError("Domain not found")
    _ensure_idle(db, "domain", domain["name"])
    job_id = _insert_job("domain", domain["name"], username)
    log_event("info", "scan.domain.queued", "Public domain scan queued", domain["name"], username)
    _pool().submit(_run_domain_scan, app, job_id, domain_id, username)
    return job_id


def _create_domain_check(db, domain_id: int, kind: str, username: str):
    domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not domain:
        raise ValueError("Domain not found")
    _ensure_idle(db, kind, domain["name"])
    check_cursor = db.execute(
        "INSERT INTO domain_checks(domain_id,kind,username,status,started_at) VALUES(?,?,?,?,?)",
        (domain_id, kind, username, "queued", now()),
    )
    job_cursor = db.execute(
        "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
        (kind, domain["name"], username, "queued", now()),
    )
    db.commit()
    return domain, check_cursor.lastrowid, job_cursor.lastrowid


def _run_origin_check(app, job_id: int, check_id: int, domain_id: int, origin_ips: str, username: str) -> None:
    with app.app_context():
        db = get_db()
        _set_job(job_id, "running")
        db.execute("UPDATE domain_checks SET status='running' WHERE id=?", (check_id,))
        db.commit()
        domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
        try:
            if not domain:
                raise ValueError("Domain no longer exists")
            result, summary, details = provider_checks.check_origin(
                domain["name"],
                origin_ips,
                json.loads(domain["tls_summary"]),
                json.loads(domain["http_summary"]),
                domain["last_scanned"] or "",
            )
            db.execute(
                "UPDATE domain_checks SET status='completed',result=?,summary=?,details=?,finished_at=? WHERE id=?",
                (result, summary, json.dumps(details), now(), check_id),
            )
            db.commit()
            message = f"Origin reachability for {domain['name']}: {result}"
            _set_job(job_id, "completed", message)
            log_event("warning" if result == "reachable" else "info", "domain.origin_check", message, domain["name"], username)
        except Exception as exc:  # noqa: BLE001 - check failures must always be recorded.
            message = _redact(str(exc), *origin_ips.split(","))
            db.execute(
                "UPDATE domain_checks SET status='failed',summary=?,finished_at=? WHERE id=?",
                (message, now(), check_id),
            )
            db.commit()
            _set_job(job_id, "failed", message)
            log_event("error", "domain.origin_check", message, domain["name"] if domain else str(domain_id), username)


def submit_origin_check(app, domain_id: int, origin_ips: str, username: str) -> tuple[int, int]:
    addresses = provider_checks.normalize_origin_ips(origin_ips)
    db = get_db()
    domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not domain:
        raise ValueError("Domain not found")
    # Origin results are only meaningful next to edge data, so refuse to guess.
    if not domain["last_scanned"]:
        raise provider_checks.ProviderCheckError("Scan the domain first; origin results are compared with the edge")
    edge_addresses = set(json.loads(domain["addresses"]))
    if edge_addresses.intersection(addresses):
        raise provider_checks.ProviderCheckError("A supplied IP is the current public edge address, not an origin")
    domain, check_id, job_id = _create_domain_check(db, domain_id, "origin", username)
    log_event("info", "domain.origin_check.queued", "Origin reachability check queued", domain["name"], username)
    _pool().submit(_run_origin_check, app, job_id, check_id, domain_id, ",".join(addresses), username)
    return job_id, check_id


def _run_cloudflare_check(app, job_id: int, check_id: int, domain_id: int, username: str) -> None:
    with app.app_context():
        db = get_db()
        _set_job(job_id, "running")
        db.execute("UPDATE domain_checks SET status='running' WHERE id=?", (check_id,))
        db.commit()
        domain = db.execute("SELECT name FROM domains WHERE id=?", (domain_id,)).fetchone()
        try:
            if not domain:
                raise ValueError("Domain no longer exists")
            result, summary, details = cloudflare_checks.check_cloudflare(domain["name"])
            db.execute(
                "UPDATE domain_checks SET status='completed',result=?,summary=?,details=?,finished_at=? WHERE id=?",
                (result, summary, json.dumps(details), now(), check_id),
            )
            db.commit()
            message = f"Cloudflare configuration for {domain['name']}: {result}"
            _set_job(job_id, "completed", message)
            log_event("warning" if result == "fail" else "info", "domain.cloudflare_check", message, domain["name"], username)
        except Exception as exc:  # noqa: BLE001 - check failures must always be recorded.
            db.execute(
                "UPDATE domain_checks SET status='failed',summary=?,finished_at=? WHERE id=?",
                (str(exc), now(), check_id),
            )
            db.commit()
            _set_job(job_id, "failed", str(exc))
            log_event("error", "domain.cloudflare_check", str(exc), domain["name"] if domain else str(domain_id), username)


def submit_cloudflare_check(app, domain_id: int, username: str) -> tuple[int, int]:
    if not app.config["CLOUDFLARE_API_TOKEN"]:
        raise cloudflare_checks.CloudflareCheckError("Set CVESCOUT_CLOUDFLARE_API_TOKEN before running this check")
    db = get_db()
    domain, check_id, job_id = _create_domain_check(db, domain_id, "cloudflare", username)
    log_event("info", "domain.cloudflare_check.queued", "Cloudflare configuration check queued", domain["name"], username)
    _pool().submit(_run_cloudflare_check, app, job_id, check_id, domain_id, username)
    return job_id, check_id


def _run_vulnerability_check(app, job_id: int, check_id: int, vulnerability_id: int, username: str) -> None:
    with app.app_context():
        db = get_db()
        _set_job(job_id, "running")
        db.execute("UPDATE checks SET status='running' WHERE id=?", (check_id,))
        db.commit()
        row = db.execute(
            "SELECT v.cve_id,p.port,d.address FROM vulnerabilities v "
            "JOIN ports p ON p.id=v.port_id JOIN devices d ON d.id=p.device_id WHERE v.id=?",
            (vulnerability_id,),
        ).fetchone()
        try:
            if not row:
                raise ValueError("Vulnerability no longer exists")
            status, details = checks.run_check(row["address"], row["port"], row["cve_id"])
            db.execute(
                "UPDATE checks SET status=?,result=?,details=?,finished_at=? WHERE id=?",
                ("completed", status, details, now(), check_id),
            )
            db.commit()
            message = f"{row['cve_id']} check: {status}"
            _set_job(job_id, "completed", message)
            if status == "vulnerable":
                notify.notify(
                    f"{row['cve_id']} confirmed vulnerable on {row['address']}",
                    f"Port {row['port']} responded as vulnerable. {details[:400]}",
                    "high",
                )
            log_event("warning" if status == "vulnerable" else "info", "vulnerability.check", message, row["address"], username)
        except Exception as exc:  # noqa: BLE001 - check failures must always be recorded.
            db.execute(
                "UPDATE checks SET status='failed',details=?,finished_at=? WHERE id=?",
                (str(exc), now(), check_id),
            )
            db.commit()
            _set_job(job_id, "failed", str(exc))
            log_event("error", "vulnerability.check", str(exc), str(vulnerability_id), username)


def submit_check(app, vulnerability_id: int, username: str) -> tuple[int, int]:
    db = get_db()
    if not db.execute("SELECT 1 FROM vulnerabilities WHERE id=?", (vulnerability_id,)).fetchone():
        raise ValueError("Vulnerability not found")
    _ensure_idle(db, "check", str(vulnerability_id))
    check_cursor = db.execute(
        "INSERT INTO checks(vulnerability_id,username,status,started_at) VALUES(?,?,?,?)",
        (vulnerability_id, username, "queued", now()),
    )
    job_cursor = db.execute(
        "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
        ("check", str(vulnerability_id), username, "queued", now()),
    )
    db.commit()
    check_id, job_id = check_cursor.lastrowid, job_cursor.lastrowid
    log_event("info", "vulnerability.check.queued", "Vulnerability check queued", str(vulnerability_id), username)
    _pool().submit(_run_vulnerability_check, app, job_id, check_id, vulnerability_id, username)
    return job_id, check_id

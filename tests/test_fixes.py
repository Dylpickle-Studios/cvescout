from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from cvescout import auth, create_app
from cvescout.db import get_db, init_db, now
from cvescout.domain_scanner import scan_domain
from cvescout.jobs import (
    JobBusy,
    _run_origin_check,
    submit_domain_scan,
    submit_scan,
)


class FixesTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        auth._login_failures.clear()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "test.sqlite3"),
                "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _domain(self, name: str = "app.example.com") -> int:
        db = get_db()
        domain_id = db.execute("INSERT INTO domains(name,created_at) VALUES(?,?)", (name, now())).lastrowid
        db.commit()
        return domain_id

    def test_restart_fails_abandoned_vulnerability_checks(self):
        with self.app.app_context():
            db = get_db()
            device_id = db.execute("INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.50.2", "up", now())).lastrowid
            port_id = db.execute("INSERT INTO ports(device_id,port,protocol,state,last_seen) VALUES(?,?,?,?,?)", (device_id, 443, "tcp", "open", now())).lastrowid
            vulnerability_id = db.execute("INSERT INTO vulnerabilities(port_id,cve_id,source,last_seen) VALUES(?,?,?,?)", (port_id, "CVE-2014-0160", "NVD", now())).lastrowid
            db.execute("INSERT INTO checks(vulnerability_id,username,status,started_at) VALUES(?,?,?,?)", (vulnerability_id, "admin", "running", now()))
            db.commit()
            init_db()
            check = db.execute("SELECT status,details,finished_at FROM checks").fetchone()
        self.assertEqual(check["status"], "failed")
        self.assertIsNotNone(check["finished_at"])
        self.assertIn("restarted", check["details"])

    @patch("cvescout.jobs.provider_checks.check_origin")
    def test_origin_failure_does_not_persist_origin_ip(self, check_origin):
        origin = "93.184.216.34"
        check_origin.side_effect = RuntimeError(f"connect failed at {origin}")
        with self.app.app_context():
            db = get_db()
            domain_id = self._domain()
            check_id = db.execute(
                "INSERT INTO domain_checks(domain_id,kind,username,status,started_at) VALUES(?,?,?,?,?)",
                (domain_id, "origin", "admin", "queued", now()),
            ).lastrowid
            job_id = db.execute(
                "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
                ("origin", "app.example.com", "admin", "queued", now()),
            ).lastrowid
            db.commit()
            _run_origin_check(self.app, job_id, check_id, domain_id, origin, "admin")
            rows = [
                *db.execute("SELECT * FROM domain_checks").fetchall(),
                *db.execute("SELECT * FROM jobs").fetchall(),
                *db.execute("SELECT * FROM events").fetchall(),
            ]
            persisted = " ".join(str(value) for row in rows for value in row)
        self.assertNotIn(origin, persisted)
        self.assertIn("connect failed at <origin>", persisted)

    @patch("cvescout.domain_scanner.resolve_public_addresses", side_effect=RuntimeError("DNS down"))
    def test_failed_domain_scan_keeps_previous_last_scanned(self, _resolve):
        previous = "2026-01-01T00:00:00+00:00"
        with self.app.app_context():
            db = get_db()
            domain_id = self._domain()
            db.execute("UPDATE domains SET last_scanned=?,status='ok' WHERE id=?", (previous, domain_id))
            db.commit()
            with self.assertRaises(RuntimeError):
                scan_domain(domain_id)
            domain = db.execute("SELECT status,last_scanned FROM domains WHERE id=?", (domain_id,)).fetchone()
        self.assertEqual(domain["status"], "error")
        self.assertEqual(domain["last_scanned"], previous)

    def test_login_is_throttled_after_repeated_failures(self):
        with self.app.app_context():
            db = get_db()
            db.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                ("admin", generate_password_hash("correct horse"), now()),
            )
            db.commit()
        client = self.app.test_client()
        token = client.get("/login").get_data(as_text=True).split('name="csrf_token" value="')[1].split('"')[0]
        statuses = [
            client.post("/login", data={"csrf_token": token, "username": "admin", "password": "wrong"}).status_code
            for _ in range(7)
        ]
        self.assertNotIn(429, statuses[:5])
        self.assertEqual(statuses[-1], 429)
        with self.app.app_context():
            events = get_db().execute("SELECT action FROM events WHERE action='login.rate_limited'").fetchall()
        self.assertEqual(len(events), 1)

    @patch("cvescout.jobs._pool")
    def test_duplicate_scan_is_not_queued_twice(self, _submit):
        with self.app.app_context():
            db = get_db()
            domain_id = self._domain()
            submit_domain_scan(self.app, domain_id, "admin")
            with self.assertRaises(JobBusy):
                submit_domain_scan(self.app, domain_id, "admin")
            submit_scan(self.app, "network", None, "admin")
            with self.assertRaises(JobBusy):
                submit_scan(self.app, "network", None, "admin")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 2)

    def test_duplicate_submission_is_reported_without_second_job(self):
        with self.app.app_context():
            domain_id = self._domain()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        with patch("cvescout.views.domains.submit_domain_scan", side_effect=JobBusy("Already queued as job 3")):
            response = client.post(f"/domains/{domain_id}/scan", data={"csrf_token": "token"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Already queued as job 3", response.get_data(as_text=True))

    def test_responses_carry_security_headers(self):
        response = self.app.test_client().get("/login")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "same-origin")
        self.assertNotIn("Strict-Transport-Security", response.headers)

    def test_hsts_only_when_https_is_enabled(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "https.sqlite3"),
                "NETWORKS": [],
                "SESSION_COOKIE_SECURE": True,
            }
        )
        response = app.test_client().get("/login")
        self.assertEqual(response.headers["Strict-Transport-Security"], "max-age=15552000")


if __name__ == "__main__":
    unittest.main()

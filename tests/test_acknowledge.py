"""Tests for finding acknowledgment: routes, visibility, alerts, exports,
and persistence across rescans."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import create_app, cve
from cvescout.db import get_db, now


class AcknowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                "NETWORKS": [],
            }
        )
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.2.40','up',?)", (now(),)
            ).lastrowid
            self.port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) "
                "VALUES(?,443,'tcp','open','https','nginx','1.20.1','cpe:/a:nginx:nginx:1.20.1',?)",
                (device_id, now()),
            ).lastrowid
            self.vuln_id = db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen,match_type,first_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (self.port_id, "CVE-2024-0001", "NVD", "HIGH", 8.1, "s", "u", now(), "exact", now()),
            ).lastrowid
            self.domain_id = db.execute(
                "INSERT INTO domains(name,status,created_at) VALUES('app.example.com','warning',?)", (now(),)
            ).lastrowid
            self.finding_id = db.execute(
                "INSERT INTO domain_findings(domain_id,finding_key,severity,category,title,detail,last_seen,first_seen) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (self.domain_id, "http.hsts_missing", "medium", "headers", "HSTS header missing", "d", now(), now()),
            ).lastrowid
            db.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"

    def tearDown(self):
        self.tempdir.cleanup()

    def _ack(self, vuln_id: int, note: str = "backported fix"):
        return self.client.post(
            f"/vulnerabilities/{vuln_id}/acknowledge",
            data={"csrf_token": "token", "note": note},
            follow_redirects=True,
        )

    def _ids(self, kind: str, query: str = "") -> list[str]:
        payload = self.client.get(f"/reports.json{query}").get_json()
        return [finding["id"] for finding in payload["findings"] if finding["type"] == kind]

    def test_migration_adds_acknowledgment_columns(self):
        with self.app.app_context():
            for table in ("vulnerabilities", "domain_findings"):
                columns = {row["name"] for row in get_db().execute(f"PRAGMA table_info({table})")}
                self.assertTrue({"acknowledged_at", "acknowledged_by", "acknowledge_note"} <= columns, table)

    def test_acknowledge_hides_from_reports_and_device_page(self):
        response = self._ack(self.vuln_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Acknowledged", response.get_data(as_text=True))
        self.assertEqual(self._ids("cve"), [])
        device_html = self.client.get("/devices/1").get_data(as_text=True)
        self.assertIn("Acknowledged (1)", device_html)
        self.assertIn("backported fix", device_html)
        with self.app.app_context():
            row = get_db().execute("SELECT acknowledged_at,acknowledged_by,acknowledge_note FROM vulnerabilities").fetchone()
            event = get_db().execute("SELECT action,username FROM events WHERE action='vulnerability.acknowledge'").fetchone()
        self.assertIsNotNone(row["acknowledged_at"])
        self.assertEqual(row["acknowledged_by"], "admin")
        self.assertEqual(row["acknowledge_note"], "backported fix")
        self.assertEqual(event["username"], "admin")

    def test_unacknowledge_restores_visibility(self):
        self._ack(self.vuln_id)
        self.client.post(f"/vulnerabilities/{self.vuln_id}/unacknowledge", data={"csrf_token": "token"})
        self.assertEqual(self._ids("cve"), ["CVE-2024-0001"])
        with self.app.app_context():
            row = get_db().execute("SELECT acknowledged_at,acknowledged_by,acknowledge_note FROM vulnerabilities").fetchone()
        self.assertIsNone(row["acknowledged_at"])
        self.assertEqual(row["acknowledge_note"], "")

    def test_reports_toggle_and_exports_include_acknowledged(self):
        self._ack(self.vuln_id)
        self.assertEqual(self._ids("cve"), [])
        self.assertEqual(self._ids("cve", "?acknowledged=1"), ["CVE-2024-0001"])
        self.assertIn("CVE-2024-0001", self.client.get("/reports.csv?acknowledged=1").get_data(as_text=True))
        self.assertNotIn("CVE-2024-0001", self.client.get("/reports.csv").get_data(as_text=True))
        page = self.client.get("/reports?acknowledged=1").get_data(as_text=True)
        self.assertIn("Hide acknowledged", page)

    def test_rescan_keeps_the_acknowledgment(self):
        self._ack(self.vuln_id)
        finding = {"cve_id": "CVE-2024-0001", "source": "NVD", "severity": "HIGH", "score": 8.1, "summary": "s", "url": "u"}
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[finding]),
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            _total, new_high = cve.correlate_port(self.port_id)
            row = get_db().execute("SELECT acknowledged_at,resolved_at FROM vulnerabilities").fetchone()
        self.assertIsNotNone(row["acknowledged_at"])
        self.assertIsNone(row["resolved_at"])
        self.assertEqual(new_high, [])  # acknowledged findings never re-alert

    def test_dashboard_counts_exclude_acknowledged(self):
        self._ack(self.vuln_id)
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("<strong>0</strong><span>CVE matches</span>", html)
        self.assertIn("<strong>1</strong><span>Acknowledged</span>", html)

    def test_note_is_capped(self):
        self._ack(self.vuln_id, note="x" * 600)
        with self.app.app_context():
            note = get_db().execute("SELECT acknowledge_note FROM vulnerabilities").fetchone()[0]
        self.assertEqual(len(note), 500)

    def test_missing_vulnerability_is_404(self):
        response = self.client.post("/vulnerabilities/999/acknowledge", data={"csrf_token": "token"})
        self.assertEqual(response.status_code, 404)

    def test_domain_finding_acknowledge_and_unacknowledge(self):
        response = self.client.post(
            f"/domain-findings/{self.finding_id}/acknowledge",
            data={"csrf_token": "token", "note": "mitigated at edge"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Acknowledged (1)", html)
        self.assertIn("mitigated at edge", html)
        self.assertEqual(self._ids("domain"), [])
        self.assertEqual(self._ids("domain", "?acknowledged=1"), ["http.hsts_missing"])
        self.client.post(f"/domain-findings/{self.finding_id}/unacknowledge", data={"csrf_token": "token"})
        self.assertEqual(self._ids("domain"), ["http.hsts_missing"])

    def test_acknowledge_requires_csrf(self):
        response = self.client.post(f"/vulnerabilities/{self.vuln_id}/acknowledge", data={"note": "x"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

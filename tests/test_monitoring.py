"""Tests for the monitoring endpoints (/healthz, /metrics) and the dashboard
findings trend."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cvescout import create_app
from cvescout.db import get_db, now
from cvescout.views.devices import _finding_trend


class MonitoringTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                "NETWORKS": [],
                "METRICS_TOKEN": "test-token",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def _login(self):
        with self.client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"

    def test_healthz_is_open_and_minimal(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True).strip(), "ok")

    def test_metrics_requires_the_bearer_token(self):
        self.assertEqual(self.client.get("/metrics").status_code, 401)
        self.assertEqual(self.client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code, 401)
        response = self.client.get("/metrics", headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.headers["Content-Type"])

    def test_metrics_disabled_without_token(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "notoken.sqlite3"),
                "NETWORKS": [],
            }
        )
        self.assertEqual(app.test_client().get("/metrics").status_code, 404)

    def test_metrics_report_inventory_and_findings(self):
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.2.40','up',?)", (now(),)
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,last_seen) VALUES(?,443,'tcp','open',?)",
                (device_id, now()),
            ).lastrowid
            db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,last_seen,first_seen) VALUES(?,?,?,?,?,?)",
                (port_id, "CVE-2024-0001", "NVD", "HIGH", now(), now()),
            )
            db.execute(
                "INSERT INTO jobs(kind,target,username,status,created_at,finished_at) VALUES('ports','','cli','completed',?,?)",
                (now(), now()),
            )
            db.commit()
        body = self.client.get("/metrics", headers={"Authorization": "Bearer test-token"}).get_data(as_text=True)
        self.assertIn('cvescout_build_info{version="', body)
        self.assertIn("cvescout_devices_total 1", body)
        self.assertIn("cvescout_devices_online 1", body)
        self.assertIn("cvescout_ports_open_total 1", body)
        self.assertIn('cvescout_vulnerabilities{state="open"} 1', body)
        self.assertIn('cvescout_vulnerabilities_open_severity{severity="HIGH"} 1', body)
        self.assertIn('cvescout_job_last_success_timestamp_seconds{kind="ports"}', body)


class TrendTests(unittest.TestCase):
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
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"

    def tearDown(self):
        self.tempdir.cleanup()

    def _seed(self):
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.2.40','up',?)", (now(),)
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,last_seen) VALUES(?,443,'tcp','open',?)",
                (device_id, now()),
            ).lastrowid
            db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,last_seen,first_seen) VALUES(?,?,?,?,?,?)",
                (port_id, "CVE-2024-0001", "NVD", "HIGH", now(), now()),
            )
            db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,last_seen,first_seen,resolved_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (port_id, "CVE-2024-0002", "NVD", "LOW", now(), now(), now()),
            )
            db.commit()

    def test_trend_counts_new_and_resolved(self):
        self._seed()
        with self.app.app_context():
            trend = _finding_trend()
        self.assertEqual(trend["new_total"], 2)
        self.assertEqual(trend["resolved_total"], 1)
        self.assertEqual(trend["peak"], 2)
        self.assertEqual(len(trend["new_points"].split()), 30)

    def test_empty_trend_is_still_renderable(self):
        with self.app.app_context():
            trend = _finding_trend()
        self.assertEqual(trend["new_total"], 0)
        self.assertEqual(trend["peak"], 1)
        self.assertTrue(trend["new_points"])

    def test_dashboard_shows_the_chart(self):
        self._seed()
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("Findings trend (30 days)", html)
        self.assertIn('class="trend-chart"', html)
        self.assertIn('class="trend-new"', html)
        self.assertIn('class="trend-resolved"', html)
        self.assertIn("2 new · 1 resolved", html)


if __name__ == "__main__":
    unittest.main()

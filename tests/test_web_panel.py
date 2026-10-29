from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cvescout import create_app
from cvescout.db import get_db, now


class WebPanelTests(unittest.TestCase):
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

    def _seed_findings(self, count: int) -> None:
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.20", "up", now())
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,last_seen) VALUES(?,?,?,?,?)",
                (device_id, 443, "tcp", "open", now()),
            ).lastrowid
            db.executemany(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?)",
                [(port_id, f"CVE-2024-{index:04d}", "NVD", "HIGH", 8.0, "s", "u", now()) for index in range(count)],
            )
            db.commit()
            return device_id

    def test_system_page_shows_build_and_profile(self):
        html = self.client.get("/system").get_data(as_text=True)
        self.assertIn("Hardware profile", html)
        self.assertIn(self.app.config["PROFILE"].name, html)
        self.assertIn("Schema version", html)
        self.assertIn("Exploit intel rows", html)
        self.assertIn(self.app.config["CVE_SOURCES"][0], html)

    def test_reports_are_paginated(self):
        self._seed_findings(60)
        first = self.client.get("/reports").get_data(as_text=True)
        self.assertIn("Page 1 of 2", first)
        self.assertIn("CVE-2024-0000", first)
        self.assertNotIn("CVE-2024-0059", first)
        second = self.client.get("/reports?page=2").get_data(as_text=True)
        self.assertIn("Page 2 of 2", second)
        self.assertIn("CVE-2024-0059", second)

    def test_exports_stay_complete_while_the_page_pages(self):
        self._seed_findings(60)
        payload = self.client.get("/reports.json").get_json()
        self.assertEqual(len(payload["findings"]), 60)

    def test_logs_page_filters_and_pages(self):
        with self.app.app_context():
            db = get_db()
            db.executemany(
                "INSERT INTO events(created_at,level,action,message) VALUES(?,?,?,?)",
                [(now(), "info" if index % 2 else "error", "test", f"event {index}") for index in range(55)],
            )
            db.commit()
        page_one = self.client.get("/logs").get_data(as_text=True)
        self.assertIn("Page 1 of 2", page_one)
        filtered = self.client.get("/logs?level=error").get_data(as_text=True)
        self.assertIn("event 0", filtered)
        self.assertNotIn("event 1<", filtered)

    def test_refresh_hook_tracks_running_jobs(self):
        idle = self.client.get("/domains").get_data(as_text=True)
        self.assertIn('data-refresh="false"', idle)
        with self.app.app_context():
            db = get_db()
            db.execute(
                "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
                ("ports", "", "admin", "running", now()),
            )
            db.commit()
        busy = self.client.get("/domains").get_data(as_text=True)
        self.assertIn('data-refresh="true"', busy)

    def test_favicon_is_served_and_cached(self):
        icon = self.client.get("/static/favicon.svg")
        self.assertEqual(icon.status_code, 200)
        self.assertIn("image/svg", icon.headers["Content-Type"])
        self.assertIn("max-age=600", icon.headers.get("Cache-Control", ""))

    def test_pages_are_login_protected(self):
        anonymous = self.app.test_client()
        for route in ("/system", "/reports", "/logs"):
            self.assertEqual(anonymous.get(route).status_code, 302, route)

    def test_device_pager_keeps_the_device_id(self):
        device_id = self._seed_findings(60)
        first = self.client.get(f"/devices/{device_id}")
        self.assertEqual(first.status_code, 200)
        html = first.get_data(as_text=True)
        self.assertIn(f"/devices/{device_id}?page=2", html)
        second = self.client.get(f"/devices/{device_id}?page=2")
        self.assertEqual(second.status_code, 200)
        self.assertIn("Page 2 of 2", second.get_data(as_text=True))

    def test_pagination_template_omits_links_on_a_single_page(self):
        self._seed_findings(2)
        html = self.client.get("/reports").get_data(as_text=True)
        self.assertNotIn("Page 1 of 1", html)


if __name__ == "__main__":
    unittest.main()

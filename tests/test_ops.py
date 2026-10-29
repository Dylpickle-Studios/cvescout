from __future__ import annotations

import ipaddress
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from cvescout import auth, create_app, db
from cvescout.db import get_db, now


class OpsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        auth._login_failures.clear()
        self.database = Path(self.tempdir.name) / "test.sqlite3"
        self.app = self._app()

    def tearDown(self):
        self.tempdir.cleanup()

    def _app(self, **overrides):
        config = {
            "TESTING": True,
            "SECRET_KEY": "test",
            "DATABASE": str(self.database),
            "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
        }
        config.update(overrides)
        return create_app(config)

    def _client(self, app=None):
        client = (app or self.app).test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        return client

    def test_schema_version_is_recorded_and_migration_is_idempotent(self):
        with self.app.app_context():
            self.assertEqual(get_db().execute("PRAGMA user_version").fetchone()[0], db.max_version())
        second = self._app()
        with second.app_context():
            self.assertEqual(get_db().execute("PRAGMA user_version").fetchone()[0], db.max_version())
            tables = {row[0] for row in get_db().execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("domain_checks", tables)

    def test_pre_versioning_database_is_migrated_without_data_loss(self):
        """Simulates an install created before schema versioning existed."""
        legacy = Path(self.tempdir.name) / "legacy.sqlite3"
        connection = sqlite3.connect(legacy)
        connection.executescript(db.SCHEMA)
        connection.execute("INSERT INTO events(created_at,level,action,message) VALUES(?,'info','kept','kept')", (now(),))
        connection.commit()
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
        connection.close()
        app = self._app(DATABASE=str(legacy))
        with app.app_context():
            self.assertEqual(get_db().execute("PRAGMA user_version").fetchone()[0], db.max_version())
            self.assertEqual(get_db().execute("SELECT action FROM events").fetchone()[0], "kept")

    def test_prune_history_removes_old_finished_rows_only(self):
        old = (datetime.now(UTC) - timedelta(days=120)).replace(microsecond=0).isoformat()
        with self.app.app_context():
            database = get_db()
            database.executescript(
                f"""
                INSERT INTO events(created_at,level,action,message) VALUES('{old}','info','old','old');
                INSERT INTO events(created_at,level,action,message) VALUES('{now()}','info','new','new');
                INSERT INTO jobs(kind,target,username,status,created_at,finished_at) VALUES('ports','','cli','completed','{old}','{old}');
                INSERT INTO jobs(kind,target,username,status,created_at) VALUES('ports','','cli','running','{old}');
                """
            )
            database.commit()
            removed = db.prune_history(90)
            events = [row["action"] for row in database.execute("SELECT action FROM events")]
            jobs = [row["status"] for row in database.execute("SELECT status FROM jobs")]
        self.assertEqual(removed, 2)
        self.assertEqual(events, ["new"])
        self.assertEqual(jobs, ["running"])

    def test_retention_disabled_keeps_everything(self):
        old = (datetime.now(UTC) - timedelta(days=400)).replace(microsecond=0).isoformat()
        app = self._app(HISTORY_RETENTION_DAYS=0)
        with app.app_context():
            database = get_db()
            database.execute("INSERT INTO events(created_at,level,action,message) VALUES(?,'info','old','old')", (old,))
            database.commit()
            self.assertEqual(db.prune_history(0), 0)
            self.assertEqual(database.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def _seed_report(self):
        with self.app.app_context():
            database = get_db()
            device_id = database.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)",
                ("192.168.50.2", "up", now()),
            ).lastrowid
            port_id = database.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (device_id, 443, "tcp", "open", "https", "nginx", "1.20", now()),
            ).lastrowid
            database.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (port_id, "CVE-2024-0001", "NVD", "HIGH", 8.1, "Example", "https://example.invalid", now()),
            )
            domain_id = database.execute(
                "INSERT INTO domains(name,provider,status,created_at) VALUES(?,?,?,?)",
                ("app.example.com", "Cloudflare", "warning", now()),
            ).lastrowid
            database.execute(
                "INSERT INTO domain_findings(domain_id,finding_key,severity,category,title,detail,last_seen) "
                "VALUES(?,?,?,?,?,?,?)",
                (domain_id, "http.hsts_missing", "medium", "headers", "HSTS header missing", "detail", now()),
            )
            database.commit()

    def test_reports_csv_and_json_export_both_sources(self):
        self._seed_report()
        client = self._client()
        csv_response = client.get("/reports.csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertTrue(csv_response.headers["Content-Type"].startswith("text/csv"))
        self.assertIn("attachment; filename=cvescout-", csv_response.headers["Content-Disposition"])
        body = csv_response.get_data(as_text=True)
        self.assertIn("CVE-2024-0001", body)
        self.assertIn("http.hsts_missing", body)

        payload = client.get("/reports.json").get_json()
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual({row["type"] for row in payload["findings"]}, {"cve", "domain"})

    def test_exports_require_login(self):
        self.assertEqual(self.app.test_client().get("/reports.csv").status_code, 302)
        self.assertEqual(self.app.test_client().get("/reports.json").status_code, 302)

    @patch("cvescout.scanner.subprocess.run")
    def test_cli_scan_runs_synchronously_and_records_job(self, run):
        run.return_value = type(
            "Result", (), {"returncode": 0, "stderr": "", "stdout": "<nmaprun><host><status state='up'/><address addr='192.168.50.9' addrtype='ipv4'/></host></nmaprun>"}
        )()
        result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "network"])
        self.assertEqual(result.exit_code, 0, result.output)
        with self.app.app_context():
            job = get_db().execute("SELECT kind,status,message,username FROM jobs").fetchone()
        self.assertEqual((job["kind"], job["status"], job["username"]), ("network", "completed", "cli"))

    def test_cli_scan_reports_failure_with_nonzero_exit(self):
        result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "ports", "--device", "999"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not found", result.output.lower())

    def test_cli_rejects_domain_filter_for_other_kinds(self):
        result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "ports", "--domain", "example.com"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--domain only applies", result.output)

    def test_login_sets_permanent_session(self):
        with self.app.app_context():
            database = get_db()
            database.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                ("admin", generate_password_hash("correct horse"), now()),
            )
            database.commit()
        client = self.app.test_client()
        token = client.get("/login").get_data(as_text=True).split('name="csrf_token" value="')[1].split('"')[0]
        client.post("/login", data={"csrf_token": token, "username": "admin", "password": "correct horse"})
        with client.session_transaction() as session:
            self.assertTrue(session.permanent)

    def test_prune_history_cli_runs(self):
        result = self.app.test_cli_runner().invoke(self.app.cli, ["prune-history", "--days", "1"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Removed", result.output)


if __name__ == "__main__":
    unittest.main()

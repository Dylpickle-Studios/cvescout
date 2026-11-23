"""Tests for the scan --kind all pipeline and the online backup command."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import create_app, db
from cvescout.db import get_db, now


class ScanAllTests(unittest.TestCase):
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

    def tearDown(self):
        self.tempdir.cleanup()

    def test_all_runs_the_pipeline_in_order(self):
        with patch("cvescout.cli.jobs.run_scan_now", return_value=("completed", "ok")) as run:
            result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "all"])
        self.assertEqual(result.exit_code, 0, result.output)
        kinds = [call.args[0] for call in run.call_args_list]
        self.assertEqual(kinds, ["network", "devices", "ports", "vulnerabilities"])
        self.assertIn("skipped domain scans", result.output)

    def test_all_includes_configured_domains(self):
        with self.app.app_context():
            get_db().execute("INSERT INTO domains(name,created_at) VALUES('app.example.com',?)", (now(),))
            get_db().commit()
        with patch("cvescout.cli.jobs.run_scan_now", return_value=("completed", "ok")) as run:
            result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "all"])
        self.assertEqual(result.exit_code, 0, result.output)
        kinds = [call.args[0] for call in run.call_args_list]
        self.assertEqual(kinds, ["network", "devices", "ports", "vulnerabilities", "domain"])

    def test_all_keeps_going_past_a_failed_stage(self):
        def run_scan(kind, device_id, username, domain_id=None):
            return ("failed", "nmap exploded") if kind == "ports" else ("completed", "ok")

        with patch("cvescout.cli.jobs.run_scan_now", side_effect=run_scan) as run:
            result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "all"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("ports", result.output)
        self.assertEqual(run.call_count, 4)  # vulnerabilities still ran

    def test_all_rejects_device_and_domain_filters(self):
        result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "all", "--device", "3"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("do not apply", result.output)


class BackupTests(unittest.TestCase):
    def test_backup_copies_database_and_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_path = Path(directory) / "secret_key"
            dest = Path(directory) / "backup"
            with patch.dict(os.environ, {"CVESCOUT_SECRET_FILE": str(secret_path)}):
                app = create_app(
                    {
                        "TESTING": True,
                        "SECRET_KEY": "test",
                        "DATABASE": str(Path(directory) / "db.sqlite3"),
                        "NETWORKS": [],
                    }
                )
                with app.app_context():
                    get_db().execute(
                        "INSERT INTO users(username,password_hash,created_at) VALUES('admin','hash',?)", (now(),)
                    )
                    get_db().commit()
                result = app.test_cli_runner().invoke(app.cli, ["backup", "--dest", str(dest)])
            self.assertEqual(result.exit_code, 0, result.output)
            backup_db = dest / "cvescout.sqlite3"
            self.assertTrue(backup_db.exists())
            connection = sqlite3.connect(backup_db)
            try:
                user = connection.execute("SELECT username FROM users").fetchone()
                version = connection.execute("PRAGMA user_version").fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(user[0], "admin")
            self.assertEqual(version, db.max_version())
            self.assertEqual((dest / "secret_key").read_bytes(), secret_path.read_bytes())
            self.assertEqual(backup_db.stat().st_mode & 0o777, 0o600)
            self.assertEqual((dest / "secret_key").stat().st_mode & 0o777, 0o600)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)

    def test_backup_into_existing_directory_keeps_its_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / "existing"
            dest.mkdir()
            dest.chmod(0o755)
            app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test",
                    "DATABASE": str(Path(directory) / "db.sqlite3"),
                    "NETWORKS": [],
                }
            )
            result = app.test_cli_runner().invoke(app.cli, ["backup", "--dest", str(dest)])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()

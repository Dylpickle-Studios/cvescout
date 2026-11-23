"""Regression tests for the review fixes.

Covers: KEV refresh preserving EPSS, source outages not resolving findings,
returning domain findings re-alerting, redirect validation, CIRCL lessThan
bounds, NVD pagination and failure pacing, the duplicate-job index, the secret
file race, stable cookie keys, probe time budgets, cache pruning, and UI counts.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import sqlite3
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from flask import template_rendered

from cvescout import circl, create_app, cve, exploit_intel, jobs
from cvescout.auth import safe_next
from cvescout.config import load_or_create_secret
from cvescout.db import MIGRATIONS, _migrate, get_db, now, prune_history
from cvescout.domain_findings import _cookie_findings
from cvescout.domain_scanner import _http_response, _replace_findings, probe_http


class AppTestCase(unittest.TestCase):
    """One fresh app and database per test, matching the other test modules."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                "NETWORKS": [],
                "NVD_API_KEY": "test-key",
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _seed_port(self) -> int:
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.2.40','up',?)", (now(),)
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) "
                "VALUES(?,443,'tcp','open','https','nginx','1.20.1','cpe:/a:nginx:nginx:1.20.1',?)",
                (device_id, now()),
            ).lastrowid
            db.commit()
        return port_id

    @staticmethod
    def _finding(cve_id: str = "CVE-2024-0001") -> dict:
        return {
            "cve_id": cve_id,
            "source": "NVD",
            "severity": "HIGH",
            "score": 8.1,
            "summary": "s",
            "url": "u",
            "match_type": "exact",
        }


class ExploitIntelRegression(AppTestCase):
    @patch("cvescout.exploit_intel._fetch")
    def test_kev_refresh_preserves_epss(self, fetch):
        fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-2024-9999"}]}
        with self.app.app_context():
            get_db().execute(
                "INSERT INTO exploit_intel(cve_id,kev,epss,checked_at) VALUES('CVE-2024-9999',1,0.95,?)",
                (now(),),
            )
            get_db().commit()
            exploit_intel.refresh_kev(force=True)
            row = get_db().execute("SELECT kev,epss FROM exploit_intel WHERE cve_id='CVE-2024-9999'").fetchone()
        self.assertEqual((row["kev"], row["epss"]), (1, 0.95))

    @patch("cvescout.exploit_intel._fetch")
    def test_kev_refresh_clears_removed_entries_without_losing_epss(self, fetch):
        fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-2024-0002"}]}
        with self.app.app_context():
            get_db().execute(
                "INSERT INTO exploit_intel(cve_id,kev,epss,checked_at) VALUES('CVE-2024-0001',1,0.5,?)",
                (now(),),
            )
            get_db().commit()
            exploit_intel.refresh_kev(force=True)
            rows = {
                row["cve_id"]: (row["kev"], row["epss"])
                for row in get_db().execute("SELECT cve_id,kev,epss FROM exploit_intel")
            }
        self.assertEqual(rows["CVE-2024-0001"], (0, 0.5))
        self.assertEqual(rows["CVE-2024-0002"][0], 1)


class OutageSafetyRegression(AppTestCase):
    def _correlate(self, port_id: int, nvd, circl_result):
        with (
            patch("cvescout.cve.lookup_cpe", nvd),
            patch("cvescout.circl.lookup_cpe", circl_result),
            self.app.app_context(),
        ):
            return cve.correlate_port(port_id)

    def test_total_outage_does_not_resolve_findings(self):
        port_id = self._seed_port()
        self._correlate(port_id, lambda cpe: [self._finding()], lambda cpe, version: [])
        self._correlate(
            port_id,
            Mock(side_effect=RuntimeError("NVD down")),
            Mock(side_effect=circl.CirclError("CIRCL down")),
        )
        with self.app.app_context():
            row = get_db().execute("SELECT resolved_at FROM vulnerabilities WHERE port_id=?", (port_id,)).fetchone()
        self.assertIsNone(row["resolved_at"])

    def test_partial_outage_does_not_resolve_findings(self):
        port_id = self._seed_port()
        self._correlate(port_id, lambda cpe: [self._finding()], lambda cpe, version: [])
        # NVD answers, CIRCL is down: absence from CIRCL is not evidence of absence.
        self._correlate(port_id, lambda cpe: [self._finding()], Mock(side_effect=circl.CirclError("down")))
        with self.app.app_context():
            row = get_db().execute("SELECT resolved_at FROM vulnerabilities WHERE port_id=?", (port_id,)).fetchone()
        self.assertIsNone(row["resolved_at"])

    def test_recovery_resolves_vanished_findings_again(self):
        port_id = self._seed_port()
        self._correlate(port_id, lambda cpe: [self._finding()], lambda cpe, version: [])
        self._correlate(
            port_id,
            Mock(side_effect=RuntimeError("NVD down")),
            Mock(side_effect=circl.CirclError("CIRCL down")),
        )
        self._correlate(port_id, lambda cpe: [], lambda cpe, version: [])
        with self.app.app_context():
            row = get_db().execute("SELECT resolved_at FROM vulnerabilities WHERE port_id=?", (port_id,)).fetchone()
        self.assertIsNotNone(row["resolved_at"])


class DomainLifecycleRegression(AppTestCase):
    def test_returning_finding_alerts_again(self):
        finding = {
            "finding_key": "http.hsts_missing",
            "severity": "medium",
            "category": "headers",
            "title": "HSTS header missing",
            "detail": "d",
            "evidence": "",
            "remediation": "",
        }
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,status,created_at) VALUES('app.example.com','never',?)", (now(),)
            ).lastrowid
            db.commit()
            first = _replace_findings(db, domain_id, [finding], now())
            db.commit()
            _replace_findings(db, domain_id, [], now())
            db.commit()
            returned = _replace_findings(db, domain_id, [finding], now())
            db.commit()
        self.assertEqual(len(first), 1)
        self.assertEqual(len(returned), 1)
        self.assertIn("HSTS header missing", returned[0])


class SafeNextRegression(unittest.TestCase):
    def test_backslash_and_control_characters_are_rejected(self):
        for value in ("/\\evil.example", "/\\/evil.example", "/\t/evil.example", "/\n/evil.example", "/x\ry"):
            self.assertIsNone(safe_next(value), value)

    def test_same_site_paths_still_pass(self):
        self.assertEqual(safe_next("/reports?page=2"), "/reports?page=2")
        self.assertIsNone(safe_next("//evil.example"))
        self.assertIsNone(safe_next("https://evil.example"))


class CirclBoundsRegression(unittest.TestCase):
    @staticmethod
    def _record(entries: list[dict]) -> dict:
        return {
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {"cna": {"affected": [{"versions": entries}]}},
        }

    def test_less_than_without_lower_bound_matches_below(self):
        record = self._record([{"status": "affected", "lessThan": "1.2.3"}])
        self.assertEqual(circl.parse_records([record], "1.0.0")[0]["match_type"], "version")
        self.assertEqual(circl.parse_records([record], "1.2.3")[0]["match_type"], "product")
        self.assertEqual(circl.parse_records([record], "1.2.4")[0]["match_type"], "product")

    def test_less_than_or_equal_is_inclusive(self):
        record = self._record([{"status": "affected", "lessThanOrEqual": "1.2.3"}])
        self.assertEqual(circl.parse_records([record], "1.2.3")[0]["match_type"], "version")
        self.assertEqual(circl.parse_records([record], "1.2.4")[0]["match_type"], "product")

    def test_lower_bound_with_less_than(self):
        record = self._record([{"status": "affected", "version": "1.0", "lessThan": "1.2.3"}])
        self.assertEqual(circl.parse_records([record], "1.1")[0]["match_type"], "version")
        self.assertEqual(circl.parse_records([record], "0.9")[0]["match_type"], "product")

    def test_zero_lower_bound_still_matches(self):
        record = self._record([{"status": "affected", "version": "0", "lessThan": "1.21.0"}])
        self.assertEqual(circl.parse_records([record], "1.20.0")[0]["match_type"], "version")
        self.assertEqual(circl.parse_records([record], "1.21.0")[0]["match_type"], "product")


class NvdRegression(AppTestCase):
    @staticmethod
    def _item(cve_id: str) -> dict:
        return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": "x"}], "metrics": {}}}

    @patch("cvescout.cve.time.sleep")
    @patch("cvescout.cve.urllib.request.urlopen")
    def test_pagination_follows_start_index(self, urlopen, _sleep):
        pages = [
            {"vulnerabilities": [self._item("CVE-2026-0001")], "resultsPerPage": 1, "totalResults": 2},
            {"vulnerabilities": [self._item("CVE-2026-0002")], "resultsPerPage": 1, "totalResults": 2},
        ]
        urlopen.side_effect = lambda *_args, **_kwargs: io.BytesIO(json.dumps(pages.pop(0)).encode())
        with self.app.app_context():
            results = cve.lookup_cpe("cpe:/a:example:server:1.0")
        self.assertEqual([item["cve_id"] for item in results], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertEqual(urlopen.call_count, 2)
        self.assertIn("startIndex=1", urlopen.call_args.args[0].full_url)

    @patch("cvescout.cve.time.sleep")
    @patch("cvescout.cve.urllib.request.urlopen", side_effect=OSError("connection reset"))
    def test_failed_attempt_is_paced(self, _urlopen, _sleep):
        previous = cve._last_request
        cve._last_request = 0.0
        try:
            with self.app.app_context(), self.assertRaises(RuntimeError):
                cve.lookup_cpe("cpe:/a:example:server:1.0")
            self.assertGreater(cve._last_request, 0.0)
        finally:
            cve._last_request = previous


class DuplicateJobRegression(AppTestCase):
    def test_insert_race_is_rejected_by_the_index(self):
        with self.app.app_context():
            jobs._insert_job("ports", "7", "admin")
            with self.assertRaises(jobs.JobBusy):
                jobs._insert_job("ports", "7", "admin")
            count = get_db().execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        self.assertEqual(count, 1)

    def test_migration_collapses_existing_duplicates(self):
        connection = sqlite3.connect(":memory:")
        for version in (1, 2, 3, 4):
            connection.executescript(MIGRATIONS[version])
        connection.execute("PRAGMA user_version = 4")
        for stamp in ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00"):
            connection.execute(
                "INSERT INTO jobs(kind,target,username,status,created_at) VALUES('ports','7','admin','queued',?)",
                (stamp,),
            )
        connection.commit()
        _migrate(connection)
        statuses = [row[0] for row in connection.execute("SELECT status FROM jobs ORDER BY id")]
        connection.close()
        self.assertEqual(statuses, ["failed", "queued"])

    def test_cli_scan_reports_busy_cleanly(self):
        with patch("cvescout.cli.jobs.run_scan_now", side_effect=jobs.JobBusy("Already queued as job 3")):
            result = self.app.test_cli_runner().invoke(self.app.cli, ["scan", "--kind", "network"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Already queued as job 3", result.output)


class SecretRaceRegression(unittest.TestCase):
    def test_lost_create_race_reads_the_winners_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_path = Path(directory) / "secret_key"

            def fake_open(path, flags, mode):
                Path(path).write_text("winner-secret")
                raise FileExistsError

            with (
                patch.dict(os.environ, {"CVESCOUT_SECRET_FILE": str(secret_path)}),
                patch("cvescout.config.os.open", side_effect=fake_open),
            ):
                self.assertEqual(load_or_create_secret(directory), "winner-secret")


class CookieKeyRegression(unittest.TestCase):
    def test_keys_follow_cookie_names_not_positions(self):
        forward = _cookie_findings({"set_cookies": ["session=abc", "theme=dark"]})
        reordered = _cookie_findings({"set_cookies": ["theme=dark", "session=abc"]})
        self.assertEqual(
            {finding["finding_key"] for finding in forward},
            {finding["finding_key"] for finding in reordered},
        )
        self.assertIn("cookie.session.secure_missing", {finding["finding_key"] for finding in forward})


class ProbeBudgetRegression(AppTestCase):
    def test_expired_budget_stops_before_connecting(self):
        with (
            patch("cvescout.domain_scanner.socket.create_connection") as connect,
            self.app.app_context(),
        ):
            result = probe_http("app.example.com", ["203.0.113.10"], deadline=time.monotonic() - 1)
        connect.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertIn("budget", result["error"])

    def test_http_response_raises_when_budget_is_spent(self):
        sock = socket.socket()
        try:
            with self.app.app_context(), self.assertRaises(socket.timeout):
                _http_response(sock, "app.example.com", time.monotonic() - 1)
        finally:
            sock.close()

    def test_body_is_read_in_bounded_chunks(self):
        client, server = socket.socketpair()
        try:
            server.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: a=1\r\n\r\nhello")
            with self.app.app_context():
                result = _http_response(client, "app.example.com", time.monotonic() + 10)
            server.recv(4096)  # drain the request before closing so the peer sees no RST
        finally:
            client.close()
            server.close()
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["body_bytes"], 5)
        self.assertEqual(result["body_sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertFalse(result["body_truncated"])

    def test_body_still_capped_at_max_bytes(self):
        client, server = socket.socketpair()
        try:
            server.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789")
            with self.app.app_context():
                self.app.config["DOMAIN_MAX_BYTES"] = 4
                result = _http_response(client, "app.example.com", time.monotonic() + 10)
            server.recv(4096)
        finally:
            client.close()
            server.close()
        self.assertEqual(result["body_bytes"], 4)
        self.assertEqual(result["body_sha256"], hashlib.sha256(b"0123").hexdigest())
        self.assertTrue(result["body_truncated"])


class PruneCacheRegression(AppTestCase):
    def test_stale_cache_payloads_are_pruned(self):
        old = (datetime.now(UTC) - timedelta(days=120)).replace(microsecond=0).isoformat()
        with self.app.app_context():
            db = get_db()
            db.execute("INSERT INTO cve_cache(cpe,payload,fetched_at) VALUES('old','[]',?)", (old,))
            db.execute("INSERT INTO cve_cache(cpe,payload,fetched_at) VALUES('new','[]',?)", (now(),))
            db.commit()
            prune_history(90)
            remaining = [row["cpe"] for row in db.execute("SELECT cpe FROM cve_cache")]
        self.assertEqual(remaining, ["new"])


class UiRegression(AppTestCase):
    def _client(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        return client

    def test_dashboard_device_counts_exclude_resolved(self):
        port_id = self._seed_port()
        with self.app.app_context():
            db = get_db()
            for cve_id in ("CVE-2024-0001", "CVE-2024-0002"):
                db.execute(
                    "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,last_seen) VALUES(?,?,?,?,?)",
                    (port_id, cve_id, "NVD", "HIGH", now()),
                )
            db.execute("UPDATE vulnerabilities SET resolved_at=? WHERE cve_id='CVE-2024-0002'", (now(),))
            db.commit()
        captured = []
        with template_rendered.connected_to(lambda sender, template, context, **extra: captured.append(context), self.app):
            self._client().get("/")
        self.assertEqual(captured[0]["devices"][0]["vulnerability_count"], 1)

    def test_domain_page_refreshes_while_a_scan_is_queued(self):
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,status,created_at) VALUES('app.example.com','never',?)", (now(),)
            ).lastrowid
            db.commit()
        client = self._client()
        idle = client.get(f"/domains/{domain_id}").get_data(as_text=True)
        self.assertIn('data-refresh="false"', idle)
        with self.app.app_context():
            get_db().execute(
                "INSERT INTO jobs(kind,target,username,status,created_at) VALUES('domain','app.example.com','admin','queued',?)",
                (now(),),
            )
            get_db().commit()
        busy = client.get(f"/domains/{domain_id}").get_data(as_text=True)
        self.assertIn('data-refresh="true"', busy)


if __name__ == "__main__":
    unittest.main()

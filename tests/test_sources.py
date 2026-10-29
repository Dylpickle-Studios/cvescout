from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import circl, create_app, cve, exploit_intel
from cvescout.db import get_db, now

NGINX_RECORD = {
    "cveMetadata": {"cveId": "CVE-2017-7529", "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "descriptions": [{"lang": "en", "value": "Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable."}],
            "affected": [{"product": "nginx", "versions": [{"version": "0.5.6 - 1.13.2", "status": "affected"}]}],
        }
    },
}

ADP_RECORD = {
    "cveMetadata": {"cveId": "CVE-2024-9999"},
    "containers": {
        "cna": {"descriptions": [{"lang": "en", "value": "Example"}], "affected": [{"versions": [{"version": "0", "lessThan": "1.21.0", "status": "affected"}]}]},
        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}],
    },
}

NO_RANGE_RECORD = {
    "cveMetadata": {"cveId": "CVE-2009-3898"},
    "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Directory traversal"}], "affected": [{"versions": [{"version": "n/a", "status": "affected"}]}]}},
}


class VersionRangeTests(unittest.TestCase):
    def test_range_labels(self):
        self.assertFalse(circl.version_in_range("1.20.1", "0.5.6 - 1.13.2"))
        self.assertTrue(circl.version_in_range("1.13.2", "0.5.6 - 1.13.2"))
        self.assertTrue(circl.version_in_range("0.5.6", "0.5.6 - 1.13.2"))
        self.assertFalse(circl.version_in_range("0.5.5", "0.5.6 - 1.13.2"))

    def test_word_separators_and_open_ended(self):
        self.assertTrue(circl.version_in_range("2.4.49", "2.4.0 through 2.4.51"))
        self.assertTrue(circl.version_in_range("1.20", "0 - 1.21.0"))
        self.assertFalse(circl.version_in_range("1.22", "0 - 1.21.0"))

    def test_exact_and_prefix(self):
        self.assertTrue(circl.version_in_range("2.4.49", "2.4.49"))
        self.assertTrue(circl.version_in_range("2.4.49", "2.4"))

    def test_junk_input_is_not_matched(self):
        self.assertFalse(circl.version_in_range("", "1.0 - 2.0"))
        self.assertFalse(circl.version_in_range("1.0", ""))
        self.assertFalse(circl.version_in_range("nginx", "n/a"))


class ParserTests(unittest.TestCase):
    def test_version_match_inside_range(self):
        findings = circl.parse_records([NGINX_RECORD], "1.13.0")
        self.assertEqual(findings[0]["cve_id"], "CVE-2017-7529")
        self.assertEqual(findings[0]["match_type"], "version")
        self.assertEqual(findings[0]["source"], "CIRCL")

    def test_outside_range_is_product_only(self):
        findings = circl.parse_records([NGINX_RECORD], "1.20.1")
        self.assertEqual(findings[0]["match_type"], "product")

    def test_missing_range_is_product_only(self):
        findings = circl.parse_records([NO_RANGE_RECORD], "1.20.1")
        self.assertEqual(findings[0]["match_type"], "product")

    def test_adp_metrics_and_less_than(self):
        findings = circl.parse_records([ADP_RECORD], "1.20.0")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["score"], 9.8)
        self.assertEqual(findings[0]["match_type"], "version")

    def test_records_without_id_are_skipped(self):
        self.assertEqual(circl.parse_records([{"containers": {}}], "1.0"), [])


class SourceMergeTests(unittest.TestCase):
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

    def _seed_port(self, cpe="cpe:/a:nginx:nginx:1.20.1"):
        db = get_db()
        device = db.execute("INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.10", "up", now())).lastrowid
        port = db.execute(
            "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
            (device, 80, "tcp", "open", "http", "nginx", "1.20.1", cpe, now()),
        ).lastrowid
        db.commit()
        return port

    def test_nvd_exact_wins_over_circl_product_match(self):
        with self.app.app_context():
            db = get_db()
            port_id = self._seed_port()
            with patch("cvescout.cve.lookup_cpe", return_value=[{"cve_id": "CVE-1", "source": "NVD", "severity": "HIGH", "score": 8.0, "summary": "nvd", "url": ""}]), patch(
                "cvescout.circl.lookup_cpe",
                return_value=[{"cve_id": "CVE-1", "source": "CIRCL", "severity": "UNKNOWN", "score": None, "summary": "circl", "url": "", "match_type": "product"}],
            ):
                total, new_high = cve.correlate_port(port_id)
            row = db.execute("SELECT * FROM vulnerabilities").fetchone()
        self.assertEqual(total, 1)
        self.assertEqual(row["match_type"], "exact")
        self.assertEqual(row["source"], "NVD")
        self.assertEqual(new_high, ["CVE-1 HIGH on port 80"])

    def test_product_only_match_is_stored_but_never_alerts(self):
        with self.app.app_context():
            db = get_db()
            port_id = self._seed_port()
            with patch("cvescout.cve.lookup_cpe", return_value=[]), patch(
                "cvescout.circl.lookup_cpe",
                return_value=[{"cve_id": "CVE-2", "source": "CIRCL", "severity": "HIGH", "score": 8.0, "summary": "guess", "url": "", "match_type": "product"}],
            ):
                total, new_high = cve.correlate_port(port_id)
            stored = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        self.assertEqual((total, stored, new_high), (1, 1, []))

    def test_failing_source_does_not_lose_the_other(self):
        with self.app.app_context():
            port_id = self._seed_port()
            with patch("cvescout.circl.lookup_cpe", side_effect=circl.CirclError("down")), patch(
                "cvescout.cve.lookup_cpe",
                return_value=[{"cve_id": "CVE-3", "source": "NVD", "severity": "LOW", "score": 2.0, "summary": "ok", "url": ""}],
            ):
                total, _ = cve.correlate_port(port_id)
        self.assertEqual(total, 1)

    def test_sources_can_be_disabled(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "nvdonly.sqlite3"),
                "NETWORKS": [],
                "CVE_SOURCES": ["nvd"],
            }
        )
        with app.app_context():
            db = get_db()
            device = db.execute("INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.11", "up", now())).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,version,cpe,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (device, 80, "tcp", "open", "http", "1.20.1", "cpe:/a:nginx:nginx:1.20.1", now()),
            ).lastrowid
            db.commit()
            with patch("cvescout.cve.lookup_cpe", return_value=[]) as nvd, patch("cvescout.circl.lookup_cpe") as circl_lookup:
                cve.correlate_port(port_id)
        self.assertTrue(nvd.called)
        circl_lookup.assert_not_called()

    def test_port_version_comes_from_the_cpe(self):
        with self.app.app_context():
            port = get_db().execute("SELECT * FROM ports WHERE id=?", (self._seed_port("cpe:/a:apache:http_server:2.4.49"),)).fetchone()
            self.assertEqual(cve._port_version(port), "2.4.49")


class ExploitIntelTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                "NETWORKS": [],
                "INTEL_REFRESH_HOURS": 24,
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_kev_catalogue_is_stored(self):
        payload = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2024-3094"}]}
        with self.app.app_context(), patch("cvescout.exploit_intel._fetch", return_value=payload):
            self.assertEqual(exploit_intel.refresh_kev(force=True), 2)
            self.assertEqual(exploit_intel.intel_for(["CVE-2021-44228"])["CVE-2021-44228"]["kev"], True)
            self.assertFalse(exploit_intel.stale())

    def test_kev_refresh_is_skipped_while_fresh(self):
        payload = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
        with self.app.app_context(), patch("cvescout.exploit_intel._fetch", return_value=payload) as fetch:
            exploit_intel.refresh_kev(force=True)
            self.assertEqual(exploit_intel.refresh_kev(), 0)
        self.assertEqual(fetch.call_count, 1)

    def test_epss_batches_and_ignores_missing(self):
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97"}, {"cve": "CVE-2024-3094", "epss": "bad"}]}
        with self.app.app_context(), patch("cvescout.exploit_intel._fetch", return_value=payload):
            self.assertEqual(exploit_intel.refresh_epss(["CVE-2021-44228", "CVE-2024-3094"]), 1)
            scores = exploit_intel.intel_for(["CVE-2021-44228", "CVE-2024-3094"])
        self.assertAlmostEqual(scores["CVE-2021-44228"]["epss"], 0.97)
        self.assertNotIn("CVE-2024-3094", scores)  # bad score is dropped, not stored as null

    def test_epss_failure_is_silent(self):
        with self.app.app_context(), patch("cvescout.exploit_intel._fetch", side_effect=OSError("offline")):
            self.assertEqual(exploit_intel.refresh_epss(["CVE-1"]), 0)
            result = exploit_intel.refresh_all(["CVE-1"])
        self.assertEqual(result["epss"], 0)

    def test_correlate_all_refreshes_intel_for_matched_cves(self):
        with self.app.app_context():
            db = get_db()
            device = db.execute("INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.12", "up", now())).lastrowid
            db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,version,cpe,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (device, 80, "tcp", "open", "http", "1.20.1", "cpe:/a:nginx:nginx:1.20.1", now()),
            )
            db.commit()
            with patch("cvescout.cve.lookup_cpe", return_value=[{"cve_id": "CVE-9", "source": "NVD", "severity": "HIGH", "score": 7.5, "summary": "x", "url": ""}]), patch(
                "cvescout.circl.lookup_cpe", return_value=[]
            ), patch("cvescout.exploit_intel.refresh_all") as refresh:
                cve.correlate_all()
        refresh.assert_called_once()
        self.assertEqual(refresh.call_args.args[0], ["CVE-9"])

    def test_refresh_intel_cli_runs(self):
        with patch("cvescout.exploit_intel.refresh_all", return_value={"kev": 5, "epss": 3}):
            result = self.app.test_cli_runner().invoke(self.app.cli, ["refresh-intel"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("KEV entries stored: 5", result.output)


class ReportRenderingTests(unittest.TestCase):
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

    def test_report_shows_kev_epss_and_match_confidence(self):
        with self.app.app_context():
            db = get_db()
            device = db.execute("INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.13", "up", now())).lastrowid
            port = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,version,cpe,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (device, 80, "tcp", "open", "http", "1.20.1", "cpe:/a:nginx:nginx:1.20.1", now()),
            ).lastrowid
            db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen,match_type) VALUES(?,?,?,?,?,?,?,?,?)",
                (port, "CVE-2021-44228", "CIRCL", "CRITICAL", 10.0, "Log4Shell", "", now(), "product"),
            )
            db.execute("INSERT INTO exploit_intel(cve_id,kev,epss,checked_at) VALUES(?,?,?,?)", ("CVE-2021-44228", 1, 0.97, now()))
            db.commit()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "t"
        html = client.get("/reports").get_data(as_text=True)
        self.assertIn("KEV", html)
        self.assertIn("97.0%", html)
        self.assertIn("product?", html)


if __name__ == "__main__":
    unittest.main()

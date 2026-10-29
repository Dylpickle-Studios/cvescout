from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import circl, create_app, cve, exploit_intel
from cvescout.db import get_db, now

CIRCL_RECORD = {
    "cveMetadata": {"cveId": "CVE-2017-7529", "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "descriptions": [{"lang": "en", "value": "Nginx range filter integer overflow."}],
            "affected": [{"product": "nginx", "versions": [{"version": "0.5.6 - 1.13.2", "status": "affected"}]}],
        },
        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}],
    },
}


def _record(cve_id: str, label: str | None, score: float | None = 9.8) -> dict:
    record = {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": f"Summary for {cve_id}"}]}},
    }
    if label:
        record["containers"]["cna"]["affected"] = [{"product": "nginx", "versions": [{"version": label, "status": "affected"}]}]
    if score is not None:
        record["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": score, "baseSeverity": "CRITICAL"}}]
    return record


class CirclParsingTests(unittest.TestCase):
    def test_version_ranges_are_matched_conservatively(self):
        self.assertTrue(circl.version_in_range("1.10.0", "0.5.6 - 1.13.2"))
        self.assertTrue(circl.version_in_range("0.5.6", "0.5.6 - 1.13.2"))
        self.assertTrue(circl.version_in_range("1.13.2", "0.5.6 - 1.13.2"))
        self.assertFalse(circl.version_in_range("1.20.1", "0.5.6 - 1.13.2"))
        self.assertTrue(circl.version_in_range("1.2.3", "1.2.0 through 1.4.0"))
        self.assertTrue(circl.version_in_range("1.20.1", "1.20.1"))
        self.assertFalse(circl.version_in_range("1.20.2", "1.20.1"))
        self.assertFalse(circl.version_in_range("", "0.5.6 - 1.13.2"))
        self.assertFalse(circl.version_in_range("n/a", "n/a"))

    def test_parse_records_marks_range_and_product_matches(self):
        findings = circl.parse_records([CIRCL_RECORD, _record("CVE-2020-0001", None)], "1.10.0")
        by_id = {item["cve_id"]: item for item in findings}
        self.assertEqual(by_id["CVE-2017-7529"]["match_type"], "version")
        self.assertEqual(by_id["CVE-2017-7529"]["severity"], "HIGH")
        self.assertEqual(by_id["CVE-2017-7529"]["score"], 7.5)
        self.assertIn("integer overflow", by_id["CVE-2017-7529"]["summary"])
        self.assertEqual(by_id["CVE-2020-0001"]["match_type"], "product")
        self.assertEqual(by_id["CVE-2020-0001"]["source"], "CIRCL")

    def test_out_of_range_version_is_only_a_product_match(self):
        findings = circl.parse_records([CIRCL_RECORD], "1.20.1")
        self.assertEqual(findings[0]["match_type"], "product")

    def test_records_without_id_are_skipped(self):
        self.assertEqual(circl.parse_records([{"containers": {}}], "1.0"), [])


class MergeTests(unittest.TestCase):
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

    @patch("cvescout.circl.lookup_cpe")
    @patch("cvescout.cve.lookup_cpe")
    def test_exact_match_beats_product_match(self, nvd, circl_lookup):
        nvd.return_value = [
            {"cve_id": "CVE-2024-0001", "source": "NVD", "severity": "HIGH", "score": 8.1, "summary": "nvd", "url": "u"}
        ]
        circl_lookup.return_value = [
            {"cve_id": "CVE-2024-0001", "source": "CIRCL", "severity": "HIGH", "score": 8.1, "summary": "circl", "url": "u", "match_type": "product"},
            {"cve_id": "CVE-2024-0002", "source": "CIRCL", "severity": "CRITICAL", "score": 9.8, "summary": "circl", "url": "u", "match_type": "version"},
        ]
        with self.app.app_context():
            merged = cve._merge_sources("cpe:2.3:a:nginx:nginx:1.20.1", "1.20.1", ["nvd", "circl"])
        by_id = {item["cve_id"]: item for item in merged}
        self.assertEqual(by_id["CVE-2024-0001"]["match_type"], "exact")
        self.assertEqual(by_id["CVE-2024-0002"]["match_type"], "version")

    @patch("cvescout.circl.lookup_cpe", side_effect=circl.CirclError("boom"))
    @patch("cvescout.cve.lookup_cpe")
    def test_one_dead_source_keeps_the_other_results(self, nvd, _circl):
        nvd.return_value = [
            {"cve_id": "CVE-2024-0003", "source": "NVD", "severity": "HIGH", "score": 7.0, "summary": "nvd", "url": "u"}
        ]
        with self.app.app_context():
            merged = cve._merge_sources("cpe:2.3:a:nginx:nginx:1.20.1", "1.20.1", ["nvd", "circl"])
        self.assertEqual([item["cve_id"] for item in merged], ["CVE-2024-0003"])

    @patch("cvescout.circl.lookup_cpe")
    @patch("cvescout.cve.lookup_cpe")
    def test_source_list_is_respected(self, nvd, circl_lookup):
        nvd.return_value = []
        with self.app.app_context():
            cve._merge_sources("cpe:2.3:a:x:y:1", "1", ["nvd"])
        circl_lookup.assert_not_called()


class CorrelateTests(unittest.TestCase):
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
                "INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.10", "up", now())
            ).lastrowid
            self.port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (device_id, 80, "tcp", "open", "http", "nginx", "1.10.0", "cpe:/a:nginx:nginx:1.10.0", now()),
            ).lastrowid
            db.commit()

    def tearDown(self):
        self.tempdir.cleanup()

    @patch("cvescout.cve.exploit_intel.refresh_all")
    @patch("cvescout.circl.lookup_cpe")
    @patch("cvescout.cve.lookup_cpe")
    def test_product_only_matches_are_stored_but_never_alert(self, nvd, circl_lookup, _refresh):
        nvd.return_value = []
        circl_lookup.return_value = [
            {"cve_id": "CVE-2020-0009", "source": "CIRCL", "severity": "HIGH", "score": 9.1, "summary": "old nginx", "url": "u", "match_type": "product"}
        ]
        with self.app.app_context():
            total, new_high = cve.correlate_port(self.port_id)
            row = get_db().execute("SELECT cve_id,source,match_type FROM vulnerabilities").fetchone()
        self.assertEqual(total, 1)
        self.assertEqual(new_high, [])
        self.assertEqual((row["source"], row["match_type"]), ("CIRCL", "product"))

    @patch("cvescout.cve.exploit_intel.refresh_all")
    @patch("cvescout.circl.lookup_cpe")
    @patch("cvescout.cve.lookup_cpe")
    def test_version_match_alerts_once(self, nvd, circl_lookup, _refresh):
        nvd.return_value = []
        circl_lookup.return_value = [
            {"cve_id": "CVE-2017-7529", "source": "CIRCL", "severity": "HIGH", "score": 7.5, "summary": "range overflow", "url": "u", "match_type": "version"}
        ]
        with self.app.app_context():
            _total, first = cve.correlate_port(self.port_id)
            _total, second = cve.correlate_port(self.port_id)
        self.assertEqual(len(first), 1)
        self.assertIn("CVE-2017-7529", first[0])
        self.assertEqual(second, [])

    @patch("cvescout.cve.exploit_intel.refresh_all")
    @patch("cvescout.circl.lookup_cpe")
    @patch("cvescout.cve.lookup_cpe")
    def test_correlate_all_refreshes_exploit_intel(self, nvd, circl_lookup, refresh):
        nvd.return_value = [
            {"cve_id": "CVE-2024-0010", "source": "NVD", "severity": "HIGH", "score": 8.0, "summary": "s", "url": "u"}
        ]
        circl_lookup.return_value = []
        with self.app.app_context():
            ports, total, _new = cve.correlate_all()
        self.assertEqual((ports, total), (1, 1))
        refresh.assert_called_once()
        self.assertIn("CVE-2024-0010", refresh.call_args.args[0])


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

    @patch("cvescout.exploit_intel._fetch")
    def test_kev_refresh_stores_and_reports_age(self, fetch):
        fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2024-3094"}]}
        with self.app.app_context():
            self.assertEqual(exploit_intel.refresh_kev(force=True), 2)
            self.assertLess(exploit_intel.kev_age_hours(), 1)
            self.assertFalse(exploit_intel.stale())
            intel = exploit_intel.intel_for(["CVE-2021-44228", "CVE-2099-0000"])
        self.assertTrue(intel["CVE-2021-44228"]["kev"])
        self.assertNotIn("CVE-2099-0000", intel)

    @patch("cvescout.exploit_intel._fetch")
    def test_kev_refresh_respects_the_cache_window(self, fetch):
        fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
        with self.app.app_context():
            exploit_intel.refresh_kev(force=True)
            self.assertEqual(exploit_intel.refresh_kev(), 0)
        self.assertEqual(fetch.call_count, 1)

    @patch("cvescout.exploit_intel._fetch")
    def test_epss_scores_are_upserted_without_clearing_kev(self, fetch):
        with self.app.app_context():
            get_db().execute(
                "INSERT INTO exploit_intel(cve_id,kev,checked_at) VALUES('CVE-2021-44228',1,?)", (now(),)
            )
            get_db().commit()
            fetch.return_value = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94300"}]}
            self.assertEqual(exploit_intel.refresh_epss(["CVE-2021-44228"]), 1)
            row = get_db().execute("SELECT kev,epss FROM exploit_intel WHERE cve_id='CVE-2021-44228'").fetchone()
        self.assertEqual((row["kev"], round(row["epss"], 4)), (1, 0.943))

    @patch("cvescout.exploit_intel._fetch", side_effect=OSError("offline"))
    def test_intel_failures_never_raise(self, _fetch):
        with self.app.app_context():
            self.assertEqual(exploit_intel.refresh_all(["CVE-2021-44228"], force_kev=True), {"kev": 0, "epss": 0})
            self.assertTrue(exploit_intel.stale())

    @patch("cvescout.exploit_intel.refresh_all", return_value={"kev": 5, "epss": 3})
    def test_cli_refresh_intel(self, refresh):
        result = self.app.test_cli_runner().invoke(self.app.cli, ["refresh-intel"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("KEV entries stored: 5", result.output)
        refresh.assert_called_once_with(force_kev=True)

    @patch("cvescout.exploit_intel._fetch")
    def test_report_orders_exploited_first(self, fetch):
        fetch.return_value = {"vulnerabilities": [{"cveID": "CVE-2020-0002"}]}
        with self.app.app_context():
            db = get_db()
            exploit_intel.refresh_kev(force=True)
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)", ("192.168.2.11", "up", now())
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,last_seen) VALUES(?,?,?,?,?)",
                (device_id, 443, "tcp", "open", now()),
            ).lastrowid
            for cve_id, score in (("CVE-2020-0001", 9.8), ("CVE-2020-0002", 5.0)):
                db.execute(
                    "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (port_id, cve_id, "NVD", "HIGH", score, "s", "u", now()),
                )
            db.commit()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "t"
        payload = client.get("/reports.json").get_json()
        order = [row["id"] for row in payload["findings"]]
        self.assertEqual(order[0], "CVE-2020-0002")


class MigrationTests(unittest.TestCase):
    def test_version_three_adds_match_type_and_intel(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test",
                    "DATABASE": str(Path(directory) / "db.sqlite3"),
                    "NETWORKS": [],
                }
            )
            with app.app_context():
                db = get_db()
                from cvescout import db as db_module

                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], db_module.max_version())
                columns = {row["name"] for row in db.execute("PRAGMA table_info(vulnerabilities)")}
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("match_type", columns)
        self.assertIn("exploit_intel", tables)


if __name__ == "__main__":
    unittest.main()

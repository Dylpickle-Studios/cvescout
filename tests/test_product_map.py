"""Tests for the explicit nmap product -> CPE map and letter-version matching."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import circl, create_app, cve
from cvescout.db import get_db, now
from cvescout.product_cpes import cpes_for


class ProductMapTests(unittest.TestCase):
    def test_openssh_patch_suffix_is_stripped(self):
        self.assertEqual(cpes_for("OpenSSH", "8.9p1"), ["cpe:/a:openbsd:openssh:8.9"])

    def test_openssl_letter_version_is_kept(self):
        self.assertEqual(cpes_for("OpenSSL", "1.1.1k"), ["cpe:/a:openssl:openssl:1.1.1k"])

    def test_vendor_churn_lists_every_candidate(self):
        self.assertEqual(
            cpes_for("MySQL", "8.0.32"),
            ["cpe:/a:mysql:mysql:8.0.32", "cpe:/a:oracle:mysql:8.0.32"],
        )

    def test_product_matching_is_case_insensitive(self):
        self.assertEqual(cpes_for("  PostgreSQL ", "15.3"), ["cpe:/a:postgresql:postgresql:15.3"])

    def test_unknown_or_versionless_products_are_skipped(self):
        self.assertEqual(cpes_for("Some Custom Daemon", "1.0"), [])
        self.assertEqual(cpes_for("OpenSSH", ""), [])
        self.assertEqual(cpes_for("nginx", "unknown"), [])


class LetterVersionTests(unittest.TestCase):
    def test_letter_releases_sort_after_the_base(self):
        self.assertTrue(circl.version_in_range("1.1.1k", "1.1.1 - 1.1.1l"))
        self.assertFalse(circl.version_in_range("1.1.1m", "1.1.1 - 1.1.1l"))

    def test_less_than_with_letter_bound(self):
        record = {
            "cveMetadata": {"cveId": "CVE-2021-0001"},
            "containers": {"cna": {"affected": [{"versions": [{"status": "affected", "lessThan": "1.1.1l"}]}]}},
        }
        self.assertEqual(circl.parse_records([record], "1.1.1k")[0]["match_type"], "version")
        self.assertEqual(circl.parse_records([record], "1.1.1l")[0]["match_type"], "product")
        self.assertEqual(circl.parse_records([record], "1.1.1")[0]["match_type"], "version")


class CorrelationFallbackTests(unittest.TestCase):
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

    def _seed_port(self, product: str, version: str, cpe: str = "") -> int:
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.2.40','up',?)", (now(),)
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) "
                "VALUES(?,22,'tcp','open','ssh',?,?,?,?)",
                (device_id, product, version, cpe, now()),
            ).lastrowid
            db.commit()
        return port_id

    @staticmethod
    def _finding() -> dict:
        return {"cve_id": "CVE-2023-38408", "source": "NVD", "severity": "HIGH", "score": 8.1, "summary": "s", "url": "u"}

    def test_port_without_cpe_uses_the_product_map(self):
        port_id = self._seed_port("OpenSSH", "8.9p1")
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[self._finding()]) as nvd,
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            total, _new = cve.correlate_port(port_id)
        self.assertEqual(total, 1)
        # correlate_port passes the mapped CPE 2.2 string; lookup_cpe normalizes it.
        nvd.assert_called_once_with("cpe:/a:openbsd:openssh:8.9")

    def test_every_candidate_cpe_is_queried(self):
        port_id = self._seed_port("MySQL", "8.0.32")
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[]) as nvd,
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            cve.correlate_port(port_id)
        self.assertEqual(nvd.call_count, 2)

    def test_nmap_cpe_still_wins_when_present(self):
        port_id = self._seed_port("OpenSSH", "8.9p1", cpe="cpe:/a:openbsd:openssh:8.9")
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[]) as nvd,
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            cve.correlate_port(port_id)
        nvd.assert_called_once_with("cpe:/a:openbsd:openssh:8.9")

    def test_unmapped_product_without_cpe_stores_nothing(self):
        port_id = self._seed_port("Custom Daemon", "1.0")
        with (
            patch("cvescout.cve.lookup_cpe") as nvd,
            patch("cvescout.circl.lookup_cpe") as circl_lookup,
            self.app.app_context(),
        ):
            total, _new = cve.correlate_port(port_id)
        self.assertEqual(total, 0)
        nvd.assert_not_called()
        circl_lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()

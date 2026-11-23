"""Tests for the expanded CVE verification: registry, state parsing, script
availability, and the payload-free version re-verification check."""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cvescout import checks, create_app
from cvescout.checks import (
    _classify,
    check_info,
    checker_for,
    run_check,
    run_version_check,
    script_available,
)
from cvescout.db import get_db, now
from cvescout.scanner import ScanError

NGINX_XML = """<nmaprun><host><ports><port protocol='tcp' portid='443'><state state='open'/>
<service name='https' product='nginx' version='{version}'><cpe>cpe:/a:nginx:nginx:{version}</cpe></service>
</port></ports></host></nmaprun>"""


class RegistryTests(unittest.TestCase):
    def test_new_allowlisted_detectors(self):
        self.assertEqual(checker_for("CVE-2017-0144"), "smb-vuln-ms17-010")
        self.assertEqual(checker_for("CVE-2017-0143"), "smb-vuln-ms17-010")
        self.assertEqual(checker_for("CVE-2012-0002"), "rdp-vuln-ms12-020")
        self.assertEqual(checker_for("CVE-2012-0152"), "rdp-vuln-ms12-020")
        self.assertIsNone(checker_for("CVE-2099-9999"))

    def test_metadata_is_available_for_the_ui(self):
        info = check_info("CVE-2017-0144")
        self.assertEqual(info["script"], "smb-vuln-ms17-010")
        self.assertTrue(info["description"])
        self.assertIsNone(check_info("CVE-2099-9999"))

    def test_dangerous_scripts_are_not_allowlisted(self):
        # These execute code on the target or can crash it.
        scripts = set(checks.SAFE_NSE_CHECKS.values())
        self.assertNotIn("http-vuln-cve2012-1823", scripts)
        self.assertNotIn("smb-vuln-ms08-067", scripts)
        self.assertNotIn("http-vuln-cve2015-1635", scripts)


class ClassifyTests(unittest.TestCase):
    def test_structured_states(self):
        self.assertEqual(_classify("State: VULNERABLE"), "vulnerable")
        self.assertEqual(_classify("State: NOT VULNERABLE"), "not_vulnerable")
        self.assertEqual(_classify("State: VULNERABLE (Exploitable)"), "vulnerable")
        self.assertEqual(_classify("State: LIKELY VULNERABLE"), "vulnerable")

    def test_mixed_states_prefer_vulnerable(self):
        details = "State: NOT VULNERABLE\nOther CVE\nState: VULNERABLE"
        self.assertEqual(_classify(details), "vulnerable")

    def test_legacy_substring_fallback(self):
        self.assertEqual(_classify("NOT VULNERABLE: patched"), "not_vulnerable")
        self.assertEqual(_classify("VULNERABLE: old nginx"), "vulnerable")
        self.assertEqual(_classify("no finding"), "inconclusive")


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
            }
        )
        checks._script_availability.clear()

    def tearDown(self):
        checks._script_availability.clear()
        self.tempdir.cleanup()

    def _seed(self, version: str = "1.20.1", match_type: str = "version") -> tuple[int, int]:
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.50.9','up',?)", (now(),)
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) "
                "VALUES(?,443,'tcp','open','https','nginx',?,?,?)",
                (device_id, version, f"cpe:/a:nginx:nginx:{version}", now()),
            ).lastrowid
            db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen,match_type,first_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (port_id, "CVE-2024-0001", "NVD", "HIGH", 8.1, "s", "u", now(), match_type, now()),
            )
            db.commit()
        return device_id, port_id


class AvailabilityTests(AppTestCase):
    @patch("cvescout.checks.subprocess.run")
    def test_available_script_is_detected_and_cached(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout="smb-vuln-ms17-010\nCategories: safe vuln", stderr="")
        with self.app.app_context():
            self.assertTrue(script_available("smb-vuln-ms17-010"))
            self.assertTrue(script_available("smb-vuln-ms17-010"))
        self.assertEqual(run.call_count, 1)

    @patch("cvescout.checks.subprocess.run")
    def test_missing_script_reports_clearly(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        with self.app.app_context():
            status, details = run_check("192.168.50.9", 445, "CVE-2017-0144")
        self.assertEqual(status, "inconclusive")
        self.assertIn("not installed", details)
        self.assertIn("smb-vuln-ms17-010", details)

    @patch("cvescout.checks.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_nmap_is_not_available(self, _run):
        with self.app.app_context():
            self.assertFalse(script_available("ssl-heartbleed"))


class VersionCheckTests(AppTestCase):
    def _run(self, port_id: int, xml: str | None, nvd_results):
        patches = [patch("cvescout.circl.lookup_cpe", return_value=[])]
        if xml is not None:
            patches.append(patch("cvescout.scanner._run_nmap", return_value=ET.fromstring(xml)))
        else:
            patches.append(patch("cvescout.scanner._run_nmap", side_effect=ScanError("nmap scan timed out")))
        patches.append(patch("cvescout.cve.lookup_cpe", return_value=nvd_results))
        with self.app.app_context():
            for item in patches:
                item.start()
            try:
                return run_version_check(port_id, "CVE-2024-0001")
            finally:
                for item in patches:
                    item.stop()

    @staticmethod
    def _finding() -> dict:
        return {"cve_id": "CVE-2024-0001", "source": "NVD", "severity": "HIGH", "score": 8.1, "summary": "s", "url": "u"}

    def test_same_version_confirms_the_match(self):
        _device_id, port_id = self._seed()
        status, details = self._run(port_id, NGINX_XML.format(version="1.20.1"), [self._finding()])
        self.assertEqual(status, "version_confirmed")
        self.assertIn("1.20.1", details)
        with self.app.app_context():
            row = get_db().execute("SELECT resolved_at FROM vulnerabilities").fetchone()
        self.assertIsNone(row["resolved_at"])

    def test_upgraded_version_does_not_reproduce(self):
        _device_id, port_id = self._seed()
        status, details = self._run(port_id, NGINX_XML.format(version="1.25.3"), [])
        self.assertEqual(status, "version_not_reproduced")
        self.assertIn("1.25.3", details)
        with self.app.app_context():
            port = get_db().execute("SELECT version FROM ports").fetchone()
            row = get_db().execute("SELECT resolved_at FROM vulnerabilities").fetchone()
        self.assertEqual(port["version"], "1.25.3")
        self.assertIsNotNone(row["resolved_at"])

    def test_closed_port_is_inconclusive(self):
        _device_id, port_id = self._seed()
        status, _details = self._run(port_id, "<nmaprun><host></host></nmaprun>", [self._finding()])
        self.assertEqual(status, "inconclusive")

    def test_probe_failure_is_inconclusive(self):
        _device_id, port_id = self._seed()
        status, details = self._run(port_id, None, [self._finding()])
        self.assertEqual(status, "inconclusive")
        self.assertIn("timed out", details)

    def test_dispatch_uses_version_check_for_version_matches(self):
        _device_id, port_id = self._seed()
        with (
            patch("cvescout.checks.run_version_check", return_value=("version_confirmed", "ok")) as version_check,
            self.app.app_context(),
        ):
            status, _details = run_check("192.168.50.9", 443, "CVE-2024-0001", port_id=port_id, match_type="version")
        self.assertEqual(status, "version_confirmed")
        version_check.assert_called_once_with(port_id, "CVE-2024-0001")

    def test_product_only_match_stays_unsupported_with_guidance(self):
        _device_id, port_id = self._seed(match_type="product")
        with self.app.app_context():
            status, details = run_check("192.168.50.9", 443, "CVE-2024-0001", port_id=port_id, match_type="product")
        self.assertEqual(status, "unsupported")
        self.assertIn("product-only", details)


if __name__ == "__main__":
    unittest.main()

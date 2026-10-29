from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from cvescout import create_app
from cvescout.checks import checker_for
from cvescout.cve import _parse_response, normalize_cpe
from cvescout.scanner import ScanError, _port_records, validate_target


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "test.sqlite3"),
                "NETWORKS": [__import__("ipaddress").ip_network("192.168.50.0/24")],
                "MAX_NETWORK_HOSTS": 256,
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_cpe_22_converts_to_cpe_23(self):
        self.assertEqual(
            normalize_cpe("cpe:/a:apache:http_server:2.4.49"),
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )

    def test_target_must_be_inside_configured_network(self):
        with self.app.app_context():
            self.assertEqual(validate_target("192.168.50.7"), "192.168.50.7")
            with self.assertRaises(ScanError):
                validate_target("8.8.8.8")

    def test_nmap_open_port_parser(self):
        root = ET.fromstring(
            """<nmaprun><host><ports><port protocol='tcp' portid='443'><state state='open'/>
            <service name='https' product='nginx' version='1.20'><cpe>cpe:/a:nginx:nginx:1.20</cpe></service>
            </port><port protocol='tcp' portid='22'><state state='closed'/></port></ports></host></nmaprun>"""
        )
        ports = _port_records(root)
        self.assertEqual(len(ports), 1)
        self.assertEqual((ports[0]["port"], ports[0]["product"]), (443, "nginx"))

    def test_nvd_response_normalization(self):
        parsed = _parse_response(
            {"vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "Example"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]}}}]}
        )
        self.assertEqual(parsed[0]["cve_id"], "CVE-2024-0001")
        self.assertEqual(parsed[0]["score"], 8.1)

    def test_active_check_is_allowlisted(self):
        self.assertEqual(checker_for("CVE-2014-0160"), "ssl-heartbleed")
        self.assertIsNone(checker_for("CVE-2099-9999"))

    def test_dashboard_requires_login(self):
        response = self.app.test_client().get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()

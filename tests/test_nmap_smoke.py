"""Smoke tests that run real Nmap against loopback.

Every other scanner test uses hand-written XML fixtures; these exercise the
production parser against actual Nmap output. They skip when nmap is not
installed; CI installs nmap and runs them explicitly so a missing binary
cannot silently skip the gate.
"""

from __future__ import annotations

import ipaddress
import shutil
import tempfile
import unittest
from pathlib import Path

from cvescout import checks, create_app, scanner
from cvescout.db import get_db, now


@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class NmapSmokeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                # A /32 keeps the network inside MAX_NETWORK_HOSTS.
                "NETWORKS": [ipaddress.ip_network("127.0.0.1/32")],
                "PORTS": "22,80,443",
                "SCAN_TIMEOUT": 60,
                "CHECK_TIMEOUT": 60,
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_real_nmap_xml_parses(self):
        with self.app.app_context():
            root = scanner._run_nmap(["-Pn", "-p", "22,80,443", "127.0.0.1"])
        self.assertEqual(root.tag, "nmaprun")
        addresses = [a.get("addr") for a in root.findall("host/address")]
        self.assertIn("127.0.0.1", addresses)

    def test_loopback_port_scan_persists(self):
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('127.0.0.1','up',?)", (now(),)
            ).lastrowid
            db.commit()
            count = scanner.scan_device_ports(device_id)
            self.assertIsInstance(count, int)
            self.assertGreaterEqual(count, 0)
            device = db.execute("SELECT status FROM devices WHERE id=?", (device_id,)).fetchone()
            self.assertEqual(device["status"], "up")
            for port in db.execute("SELECT * FROM ports"):
                self.assertIn(port["state"], {"open"})
                self.assertIsInstance(port["port"], int)

    def test_script_check_runs_real_nmap(self):
        checks._script_availability.clear()
        with self.app.app_context():
            # Port 59999 is closed on loopback, so the detector reports no finding.
            status, details = checks.run_check("127.0.0.1", 59999, "CVE-2014-0160")
        self.assertIn(status, {"vulnerable", "not_vulnerable", "inconclusive"})
        self.assertTrue(details)


if __name__ == "__main__":
    unittest.main()

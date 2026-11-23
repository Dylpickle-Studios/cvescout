"""Tests for opt-in UDP scanning and protocol-aware verification."""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cvescout import checks, create_app, scanner
from cvescout.db import get_db, now

UDP_XML = """<nmaprun><host><ports>
<port protocol='udp' portid='161'><state state='open'/>
<service name='snmp' product='net-snmp' version='5.9'><cpe>cpe:/a:net-snmp:net-snmp:5.9</cpe></service></port>
<port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='8.9p1'/></port>
</ports></host></nmaprun>"""


class UdpTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
                "PORTS": "22,80",
                "UDP_PORTS": "53,161",
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _seed_device(self) -> int:
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.50.9','up',?)", (now(),)
            ).lastrowid
            db.commit()
        return device_id

    @patch("cvescout.scanner.subprocess.run")
    def test_combined_tcp_udp_scan(self, run):
        run.return_value = SimpleNamespace(returncode=0, stderr="", stdout=UDP_XML)
        device_id = self._seed_device()
        with self.app.app_context():
            count = scanner.scan_device_ports(device_id)
            ports = {
                (row["port"], row["protocol"]): row
                for row in get_db().execute("SELECT * FROM ports")
            }
        self.assertEqual(count, 2)
        self.assertIn((161, "udp"), ports)
        self.assertEqual(ports[(161, "udp")]["product"], "net-snmp")
        command = run.call_args.args[0]
        self.assertIn("-sU", command)
        self.assertIn("T:22,80,U:53,161", command)

    @patch("cvescout.scanner.subprocess.run")
    def test_udp_off_by_default(self, run):
        run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="<nmaprun><host></host></nmaprun>")
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "tcp.sqlite3"),
                "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
            }
        )
        with app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.50.9','up',?)", (now(),)
            ).lastrowid
            db.commit()
            scanner.scan_device_ports(device_id)
        command = run.call_args.args[0]
        self.assertNotIn("-sU", command)

    @patch("cvescout.checks.subprocess.run")
    def test_script_check_targets_udp_port(self, run):
        checks._script_availability["ssl-heartbleed"] = True
        run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="<nmaprun><host></host></nmaprun>")
        try:
            with self.app.app_context():
                checks.run_check("192.168.50.9", 443, "CVE-2014-0160", protocol="udp")
        finally:
            checks._script_availability.clear()
        command = run.call_args.args[0]
        self.assertIn("-sU", command)
        self.assertIn("U:443", command)

    def test_version_check_targets_udp_port(self):
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES('192.168.50.9','up',?)", (now(),)
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,cpe,last_seen) "
                "VALUES(?,161,'udp','open','snmp','net-snmp','5.9','cpe:/a:net-snmp:net-snmp:5.9',?)",
                (device_id, now()),
            ).lastrowid
            db.execute(
                "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,last_seen,match_type,first_seen) "
                "VALUES(?,?,?,?,?,?,?)",
                (port_id, "CVE-2024-0001", "NVD", "HIGH", now(), "exact", now()),
            )
            db.commit()
        finding = {"cve_id": "CVE-2024-0001", "source": "NVD", "severity": "HIGH", "score": 8.0, "summary": "s", "url": "u"}
        with (
            patch("cvescout.scanner._run_nmap", return_value=ET.fromstring(UDP_XML)) as nmap,
            patch("cvescout.cve.lookup_cpe", return_value=[finding]),
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            status, _details = checks.run_version_check(port_id, "CVE-2024-0001")
        self.assertEqual(status, "version_confirmed")
        arguments = nmap.call_args.args[0]
        self.assertIn("-sU", arguments)
        self.assertIn("U:161", arguments)


if __name__ == "__main__":
    unittest.main()

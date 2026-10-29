from __future__ import annotations

import io
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cvescout import create_app, cve
from cvescout.checks import run_check
from cvescout.db import get_db, now
from cvescout.scanner import discover_network, scan_device_ports


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "test.sqlite3"),
                "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
                "MAX_NETWORK_HOSTS": 256,
                "NVD_API_KEY": "test-key",
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    @patch("cvescout.scanner.subprocess.run")
    def test_network_discovery_runs_nmap_and_persists_device(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout="""<nmaprun><host><status state='up'/><address addr='192.168.50.9' addrtype='ipv4'/>
            <address addr='AA:BB:CC:DD:EE:FF' addrtype='mac' vendor='Example'/>
            <hostnames><hostname name='printer.local'/></hostnames></host></nmaprun>""",
        )
        with self.app.app_context():
            self.assertEqual(discover_network(), 1)
            device = get_db().execute("SELECT * FROM devices").fetchone()
            self.assertEqual((device["address"], device["hostname"], device["vendor"]), ("192.168.50.9", "printer.local", "Example"))
        command = run.call_args.args[0]
        self.assertIn("-sn", command)
        self.assertIn("192.168.50.0/24", command)
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("cvescout.scanner.subprocess.run")
    def test_port_scan_profiles_service(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout="""<nmaprun><host><ports><port protocol='tcp' portid='443'><state state='open'/>
            <service name='https' product='nginx' version='1.20.1' extrainfo='TLS'>
            <cpe>cpe:/a:nginx:nginx:1.20.1</cpe></service></port></ports></host></nmaprun>""",
        )
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,status,last_seen) VALUES(?,?,?)",
                ("192.168.50.9", "up", now()),
            ).lastrowid
            db.commit()
            self.assertEqual(scan_device_ports(device_id), 1)
            port = db.execute("SELECT * FROM ports").fetchone()
            self.assertEqual((port["port"], port["product"], port["version"]), (443, "nginx", "1.20.1"))
            self.assertEqual(port["cpe"], "cpe:/a:nginx:nginx:1.20.1")
        command = run.call_args.args[0]
        self.assertIn("-sV", command)
        self.assertIn("192.168.50.9", command)

    @patch("cvescout.cve.time.sleep")
    @patch("cvescout.cve.urllib.request.urlopen")
    def test_nvd_lookup_is_cached(self, urlopen, sleep):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.0}}]},
                    }
                }
            ]
        }
        urlopen.side_effect = lambda *_args, **_kwargs: io.BytesIO(json.dumps(payload).encode())
        previous_request = cve._last_request
        cve._last_request = 0.0
        try:
            with self.app.app_context():
                first = cve.lookup_cpe("cpe:/a:example:server:1.0")
                second = cve.lookup_cpe("cpe:/a:example:server:1.0")
                self.assertEqual(first, second)
                self.assertEqual(first[0]["cve_id"], "CVE-2026-1234")
                self.assertEqual(get_db().execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0], 1)
        finally:
            cve._last_request = previous_request
        self.assertEqual(urlopen.call_count, 1)
        self.assertIn("isVulnerable", urlopen.call_args.args[0].full_url)
        sleep.assert_not_called()

    @patch("cvescout.checks.subprocess.run")
    def test_explicit_check_uses_only_mapped_script(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout="""<nmaprun><host><ports><port><script id='ssl-heartbleed' output='NOT VULNERABLE'/></port></ports></host></nmaprun>""",
        )
        with self.app.app_context():
            result, details = run_check("192.168.50.9", 443, "CVE-2014-0160")
            self.assertEqual(result, "not_vulnerable")
            self.assertIn("NOT VULNERABLE", details)
            unsupported = run_check("192.168.50.9", 443, "CVE-2099-9999")
            self.assertEqual(unsupported[0], "unsupported")
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--script") + 1], "ssl-heartbleed")
        self.assertNotIn("CVE-2014-0160", command)


if __name__ == "__main__":
    unittest.main()

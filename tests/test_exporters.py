from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from cvescout import create_app, exporters
from cvescout.db import get_db, now


class ExporterTests(unittest.TestCase):
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
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"

    def tearDown(self):
        self.tempdir.cleanup()

    def _seed(self, findings: int = 3) -> int:
        with self.app.app_context():
            db = get_db()
            device_id = db.execute(
                "INSERT INTO devices(address,hostname,status,last_seen) VALUES(?,?,?,?)",
                ("192.168.2.30", "nas.lan", "up", now()),
            ).lastrowid
            port_id = db.execute(
                "INSERT INTO ports(device_id,port,protocol,state,service,product,version,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (device_id, 443, "tcp", "open", "https", "nginx", "1.20.1", now()),
            ).lastrowid
            for index in range(findings):
                db.execute(
                    "INSERT INTO vulnerabilities(port_id,cve_id,source,severity,score,summary,url,last_seen,match_type) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        port_id,
                        f"CVE-2024-{index:04d}",
                        "NVD",
                        "HIGH",
                        8.1,
                        "Example summary",
                        f"https://nvd.nist.gov/vuln/detail/CVE-2024-{index:04d}",
                        now(),
                        "exact",
                    ),
                )
            db.execute("INSERT INTO exploit_intel(cve_id,kev,epss,checked_at) VALUES('CVE-2024-0000',1,0.97,?)", (now(),))
            db.commit()
            return device_id

    def test_csv_carries_risk_and_match_columns(self):
        self._seed()
        body = self.client.get("/reports.csv").get_data(as_text=True)
        reader = csv.DictReader(io.StringIO(body))
        self.assertEqual(reader.fieldnames, exporters.REPORT_FIELDS)
        rows = list(reader)
        self.assertEqual(len(rows), 3)
        kev_row = next(row for row in rows if row["id"] == "CVE-2024-0000")
        self.assertEqual(kev_row["kev"], "True")
        self.assertEqual(kev_row["match"], "exact")
        self.assertEqual(kev_row["source"], "NVD")

    def test_sarif_document_is_valid_and_ordered(self):
        self._seed()
        response = self.client.get("/reports.sarif")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/sarif+json")
        self.assertIn("attachment; filename=cvescout-", response.headers["Content-Disposition"])
        document = json.loads(response.get_data(as_text=True))
        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "CVE Scout")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 3)
        self.assertEqual(len(run["results"]), 3)
        first = run["results"][0]
        self.assertEqual(first["ruleId"], "CVE-2024-0000")
        self.assertEqual(first["level"], "error")
        self.assertTrue(first["properties"]["knownExploited"])
        self.assertIn("nas.lan:443/tcp", first["message"]["text"])  # hostname wins over address
        self.assertTrue(first["partialFingerprints"]["cvescout/v1"])

    def test_sarif_levels_follow_severity(self):
        rows = [
            {"type": "cve", "id": "CVE-1", "severity": "CRITICAL", "score": 9.8, "target": "h", "port": "1/tcp",
             "service": "", "match": "exact", "source": "NVD", "kev": False, "epss": None, "title": "t",
             "last_check": "", "last_seen": "", "url": ""},
            {"type": "domain", "id": "low", "severity": "low", "score": None, "target": "d", "port": "",
             "service": "", "match": "config", "source": "domain", "kev": False, "epss": None, "title": "t",
             "last_check": "", "last_seen": "", "url": ""},
            {"type": "domain", "id": "unk", "severity": "UNKNOWN", "score": None, "target": "d", "port": "",
             "service": "", "match": "config", "source": "domain", "kev": False, "epss": None, "title": "t",
             "last_check": "", "last_seen": "", "url": ""},
        ]
        levels = [result["level"] for result in exporters.to_sarif(rows, "0", "now")["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "note", "note"])

    def test_fingerprints_are_stable_and_target_specific(self):
        row = {"type": "cve", "id": "CVE-9", "severity": "HIGH", "score": 7.0, "target": "192.168.2.30",
               "port": "443/tcp", "service": "https", "match": "exact", "source": "NVD", "kev": False,
               "epss": None, "title": "t", "last_check": "", "last_seen": "", "url": ""}
        other = dict(row, target="192.168.2.31")
        first = exporters.to_sarif([row], "0", "now")["runs"][0]["results"][0]
        again = exporters.to_sarif([row], "0", "later")["runs"][0]["results"][0]
        moved = exporters.to_sarif([other], "0", "now")["runs"][0]["results"][0]
        self.assertEqual(first["partialFingerprints"], again["partialFingerprints"])
        self.assertNotEqual(first["partialFingerprints"], moved["partialFingerprints"])

    def test_device_exports_are_scoped_to_one_host(self):
        device_id = self._seed()
        payload = self.client.get(f"/devices/{device_id}.json").get_json()
        self.assertEqual(payload["count"], 3)
        self.assertEqual(payload["device"]["address"], "192.168.2.30")
        self.assertEqual(payload["device"]["hostname"], "nas.lan")

        csv_response = self.client.get(f"/devices/{device_id}.csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn("192.168.2.30", csv_response.headers["Content-Disposition"])
        rows = list(csv.DictReader(io.StringIO(csv_response.get_data(as_text=True))))
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["target"] for row in rows}, {"nas.lan"})

    def test_unknown_device_export_is_404(self):
        self.assertEqual(self.client.get("/devices/999.json").status_code, 404)
        self.assertEqual(self.client.get("/devices/999.csv").status_code, 404)

    def test_exports_require_login(self):
        anonymous = self.app.test_client()
        for route in ("/reports.csv", "/reports.json", "/reports.sarif", "/devices/1.json", "/devices/1.csv"):
            self.assertEqual(anonymous.get(route).status_code, 302, route)

    def test_empty_report_exports_do_not_crash(self):
        self.assertEqual(self.client.get("/reports.sarif").status_code, 200)
        self.assertEqual(self.client.get("/reports.csv").status_code, 200)
        self.assertEqual(self.client.get("/reports.json").get_json()["count"], 0)


if __name__ == "__main__":
    unittest.main()

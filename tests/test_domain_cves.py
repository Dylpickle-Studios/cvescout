"""Tests for passive domain CVE correlation: header software extraction and
source-backed findings with the same confidence policy as local matches."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import circl, create_app
from cvescout.db import get_db, now
from cvescout.domain_cves import correlate_software, extract_software


class ExtractSoftwareTests(unittest.TestCase):
    def test_common_disclosure_headers(self):
        https = {"ok": True, "headers": {"server": "nginx/1.20.1", "x-powered-by": "PHP/7.4.3"}}
        software = extract_software(https)
        by_product = {item["product"]: item for item in software}
        self.assertEqual(by_product["nginx"]["cpe"], "cpe:/a:nginx:nginx:1.20.1")
        self.assertEqual(by_product["php"]["cpe"], "cpe:/a:php:php:7.4.3")
        self.assertEqual(by_product["php"]["header"], "x-powered-by")

    def test_multi_token_server_header(self):
        https = {"ok": True, "headers": {"server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1k"}}
        software = extract_software(https)
        self.assertEqual(len(software), 1)  # OpenSSL is deliberately not mapped
        self.assertEqual(software[0]["cpe"], "cpe:/a:apache:http_server:2.4.49")

    def test_iis_and_openresty(self):
        https = {"ok": True, "headers": {"server": "Microsoft-IIS/10.0"}}
        http = {"ok": True, "headers": {"server": "openresty/1.19.3.1"}}
        software = extract_software(https, http)
        cpes = {item["cpe"] for item in software}
        self.assertIn("cpe:/a:microsoft:internet_information_services:10.0", cpes)
        self.assertIn("cpe:/a:openresty:openresty:1.19.3.1", cpes)

    def test_edge_and_versionless_servers_are_ignored(self):
        for server in ("cloudflare", "nginx", "AmazonS3", "GitHub.com", "Apache-Coyote/1.1"):
            self.assertEqual(extract_software({"ok": True, "headers": {"server": server}}), [], server)

    def test_failed_probes_are_ignored(self):
        self.assertEqual(extract_software({"ok": False, "headers": {"server": "nginx/1.20.1"}}), [])

    def test_duplicates_are_merged(self):
        probe = {"ok": True, "headers": {"server": "nginx/1.20.1"}}
        self.assertEqual(len(extract_software(probe, probe)), 1)


class CorrelateSoftwareTests(unittest.TestCase):
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
        self.software = [{"product": "nginx", "version": "1.20.1", "cpe": "cpe:/a:nginx:nginx:1.20.1", "header": "server"}]

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _nvd_finding(cve_id: str = "CVE-2021-23017", severity: str = "HIGH") -> dict:
        return {"cve_id": cve_id, "source": "NVD", "severity": severity, "score": 7.7, "summary": "nginx resolver issue", "url": "u"}

    def test_version_match_becomes_a_cve_finding(self):
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[self._nvd_finding()]),
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            findings = correlate_software(self.software)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["finding_key"], "cve.CVE-2021-23017")
        self.assertEqual(finding["category"], "cve")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("nginx", finding["title"])
        self.assertIn("server: nginx/1.20.1", finding["evidence"])
        self.assertIn("exact", finding["detail"])

    def test_product_only_lead_is_info_and_never_alerts(self):
        circl_finding = {**self._nvd_finding(), "source": "CIRCL", "match_type": "product"}
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[]),
            patch("cvescout.circl.lookup_cpe", return_value=[circl_finding]),
            self.app.app_context(),
        ):
            findings = correlate_software(self.software)
        self.assertEqual(findings[0]["severity"], "info")

    def test_kev_flag_is_noted_from_local_intel(self):
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[self._nvd_finding()]),
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            get_db().execute(
                "INSERT INTO exploit_intel(cve_id,kev,epss,checked_at) VALUES('CVE-2021-23017',1,0.5,?)", (now(),)
            )
            get_db().commit()
            findings = correlate_software(self.software)
        self.assertIn("CISA KEV", findings[0]["detail"])

    def test_source_outage_returns_no_findings_without_raising(self):
        with (
            patch("cvescout.cve.lookup_cpe", side_effect=RuntimeError("NVD down")),
            patch("cvescout.circl.lookup_cpe", side_effect=circl.CirclError("CIRCL down")),
            self.app.app_context(),
        ):
            self.assertEqual(correlate_software(self.software), [])

    def test_configured_sources_are_respected(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "nvdonly.sqlite3"),
                "NETWORKS": [],
                "CVE_SOURCES": ["nvd"],
            }
        )
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[]) as nvd,
            patch("cvescout.circl.lookup_cpe") as circl_lookup,
            app.app_context(),
        ):
            correlate_software(self.software)
        nvd.assert_called_once()
        circl_lookup.assert_not_called()

    def test_strongest_claim_wins_across_sources(self):
        circl_finding = {**self._nvd_finding(), "source": "CIRCL", "match_type": "product", "severity": "UNKNOWN", "score": None}
        with (
            patch("cvescout.cve.lookup_cpe", return_value=[self._nvd_finding()]),
            patch("cvescout.circl.lookup_cpe", return_value=[circl_finding]),
            self.app.app_context(),
        ):
            findings = correlate_software(self.software)
        self.assertEqual(len(findings), 1)
        self.assertIn("NVD", findings[0]["detail"])
        self.assertEqual(findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()

"""Tests for CMS detection from meta generator / X-Generator and its CVE
correlation, plus the small login-timing and cache-header hardening."""

from __future__ import annotations

import re
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import create_app, cve
from cvescout.db import get_db, now
from cvescout.domain_cves import extract_software
from cvescout.domain_scanner import (
    _generator_from_body,
    _http_response,
    _stored_probe,
    scan_domain,
)


class GeneratorExtractionTests(unittest.TestCase):
    def test_standard_meta_generator(self):
        body = b'<html><head><meta name="generator" content="WordPress 6.2.2"></head></html>'
        self.assertEqual(_generator_from_body(body), "WordPress 6.2.2")

    def test_attribute_order_and_quotes(self):
        body = b"<meta content='Joomla! 3.9' name='generator'>"
        self.assertEqual(_generator_from_body(body), "Joomla! 3.9")

    def test_unquoted_content(self):
        body = b"<meta name=generator content=WordPress>"
        self.assertEqual(_generator_from_body(body), "WordPress")

    def test_no_generator(self):
        self.assertEqual(_generator_from_body(b"<html><head><title>x</title></head></html>"), "")
        self.assertEqual(_generator_from_body(b'<meta name="description" content="x">'), "")


class CmsSoftwareTests(unittest.TestCase):
    def test_wordpress_from_generator(self):
        software = extract_software({"ok": True, "headers": {}, "generator": "WordPress 6.2.2"})
        self.assertEqual(software[0]["cpe"], "cpe:/a:wordpress:wordpress:6.2.2")
        self.assertEqual(software[0]["header"], "meta generator")

    def test_drupal_from_x_generator_header(self):
        software = extract_software({"ok": True, "headers": {"x-generator": "Drupal 10 (https://www.drupal.org)"}})
        self.assertEqual(software[0]["cpe"], "cpe:/a:drupal:drupal:10")

    def test_joomla_cpe_escapes_the_exclamation(self):
        software = extract_software({"ok": True, "headers": {}, "generator": "Joomla! 3.9"})
        self.assertEqual(software[0]["cpe"], "cpe:/a:joomla:joomla\\!:3.9")
        self.assertEqual(cve.normalize_cpe(software[0]["cpe"]), "cpe:2.3:a:joomla:joomla\\!:3.9:*:*:*:*:*:*:*")

    def test_versionless_generator_is_skipped(self):
        self.assertEqual(extract_software({"ok": True, "headers": {}, "generator": "WordPress"}), [])

    def test_generator_and_headers_combine(self):
        probe = {"ok": True, "headers": {"server": "nginx/1.20.1"}, "generator": "WordPress 6.2.2"}
        products = {item["product"] for item in extract_software(probe)}
        self.assertEqual(products, {"nginx", "wordpress"})


class GeneratorProbeTests(unittest.TestCase):
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

    def test_http_response_captures_generator_not_body(self):
        body = b'<html><head><meta name="generator" content="WordPress 6.2.2"></head><body>secret page</body></html>'
        client, server = socket.socketpair()
        try:
            server.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            with self.app.app_context():
                result = _http_response(client, "app.example.com", time.monotonic() + 10)
            server.recv(65536)
        finally:
            client.close()
            server.close()
        self.assertEqual(result["generator"], "WordPress 6.2.2")
        stored = _stored_probe(result)
        self.assertEqual(stored["generator"], "WordPress 6.2.2")
        self.assertNotIn("body_text", stored)
        self.assertNotIn("secret page", str(stored))

    def test_scan_domain_stores_cms_cve_findings(self):
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,created_at) VALUES('blog.example.com',?)", (now(),)
            ).lastrowid
            db.commit()
        https = {
            "ok": True,
            "address": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "certificate_expires": "",
            "headers": {},
            "set_cookies": [],
            "generator": "WordPress 6.2.2",
        }
        wp_cve = {"cve_id": "CVE-2023-0001", "source": "NVD", "severity": "HIGH", "score": 8.0, "summary": "WP issue", "url": "u"}
        with (
            patch("cvescout.domain_scanner.resolve_public_addresses", return_value=["93.184.216.34"]),
            patch("cvescout.domain_scanner.collect_dns", return_value={"A": ["93.184.216.34"]}),
            patch("cvescout.domain_scanner.probe_https", return_value=https),
            patch("cvescout.domain_scanner.probe_http", return_value={"ok": True, "status": 301, "headers": {"location": "https://blog.example.com/"}, "set_cookies": []}),
            patch("cvescout.cve.lookup_cpe", return_value=[wp_cve]) as nvd,
            patch("cvescout.circl.lookup_cpe", return_value=[]),
            self.app.app_context(),
        ):
            total, new_findings = scan_domain(domain_id)
            keys = {row["finding_key"] for row in get_db().execute("SELECT finding_key FROM domain_findings")}
        nvd.assert_called_once_with("cpe:2.3:a:wordpress:wordpress:6.2.2:*:*:*:*:*:*:*")
        self.assertIn("cve.CVE-2023-0001", keys)
        self.assertGreaterEqual(total, 1)
        self.assertTrue(any("CVE-2023-0001" in label for label in new_findings))


class HardeningTests(unittest.TestCase):
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

    def tearDown(self):
        self.tempdir.cleanup()

    def test_unknown_user_still_hashes_a_password(self):
        page = self.client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        with patch("cvescout.auth.check_password_hash", return_value=False) as check:
            response = self.client.post(
                "/login", data={"csrf_token": token, "username": "nobody", "password": "x"}
            )
        check.assert_called_once()  # the dummy hash equalizes timing
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password", response.get_data(as_text=True))

    def test_pages_are_no_store_but_static_keeps_its_max_age(self):
        self.assertEqual(self.client.get("/login").headers["Cache-Control"], "no-store")
        with self.client.session_transaction() as session:
            session["user"] = "admin"
        self.assertEqual(self.client.get("/").headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/reports.json").headers["Cache-Control"], "no-store")
        static = self.client.get("/static/favicon.svg")
        self.assertIn("max-age=600", static.headers["Cache-Control"])
        self.assertNotIn("no-store", static.headers["Cache-Control"])


if __name__ == "__main__":
    unittest.main()

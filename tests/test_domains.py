from __future__ import annotations

import io
import ipaddress
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from cvescout import cloudflare_checks, create_app
from cvescout.cloudflare_checks import CloudflareCheckError, check_cloudflare
from cvescout.db import get_db, now
from cvescout.domain_findings import analyze_domain
from cvescout.domain_scanner import (
    DomainScanError,
    normalize_domain,
    probe_https,
    resolve_public_addresses,
    scan_domain,
)
from cvescout.jobs import submit_origin_check
from cvescout.provider_checks import (
    ProviderCheckError,
    check_origin,
    normalize_origin_ips,
)


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "test.sqlite3"),
                "NETWORKS": [ipaddress.ip_network("192.168.50.0/24")],
                "DOMAIN_CONNECT_TIMEOUT": 1,
                "DOMAIN_MAX_BYTES": 1024,
                "CLOUDFLARE_API_TOKEN": "test-token",
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_domain_normalization_rejects_urls(self):
        self.assertEqual(normalize_domain("WWW.Example.COM."), "www.example.com")
        with self.assertRaises(DomainScanError):
            normalize_domain("https://example.com/path")
        with self.assertRaises(DomainScanError):
            normalize_domain("localhost")

    @patch("cvescout.domain_scanner.socket.getaddrinfo")
    def test_resolution_rejects_any_private_address(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with self.assertRaisesRegex(DomainScanError, "non-public"):
            resolve_public_addresses("example.com")

    @patch("cvescout.domain_scanner._http_response")
    @patch("cvescout.domain_scanner.ssl.create_default_context")
    @patch("cvescout.domain_scanner.socket.create_connection")
    def test_https_probe_connects_to_validated_ip_with_hostname_sni(self, create_connection, create_context, http_response):
        raw = MagicMock()
        raw.__enter__.return_value = raw
        secured = MagicMock()
        secured.__enter__.return_value = secured
        secured.getpeercert.return_value = {}
        secured.version.return_value = "TLSv1.3"
        secured.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        create_connection.return_value = raw
        create_context.return_value.wrap_socket.return_value = secured
        http_response.return_value = {"status": 200, "headers": {}, "set_cookies": []}
        with self.app.app_context():
            result = probe_https("app.example.com", ["93.184.216.34"])
        self.assertTrue(result["ok"])
        create_connection.assert_called_once_with(("93.184.216.34", 443), timeout=1)
        create_context.return_value.wrap_socket.assert_called_once_with(raw, server_hostname="app.example.com")

    def test_domain_analysis_detects_cloudflare_and_configuration_findings(self):
        records = {
            "CNAME": [],
            "NS": ["alice.ns.cloudflare.com"],
            "MX": ["10 mail.example.com"],
            "TXT": ["v=spf1 +all"],
            "DMARC": ["v=DMARC1; p=none"],
        }
        https = {
            "ok": True,
            "tls_version": "TLSv1.3",
            "headers": {"server": "cloudflare", "cf-ray": "abc"},
            "set_cookies": ["session=secret"],
        }
        http = {"ok": True, "status": 200, "headers": {}}
        provider, findings = analyze_domain(records, https, http)
        keys = {finding["finding_key"] for finding in findings}
        self.assertEqual(provider, "Cloudflare")
        self.assertTrue(
            {
                "email.spf_allow_all",
                "email.dmarc_monitor_only",
                "http.hsts_missing",
                "cookie.0.secure_missing",
                "http.redirect_missing",
            }.issubset(keys)
        )

    @patch("cvescout.domain_scanner.probe_http")
    @patch("cvescout.domain_scanner.probe_https")
    @patch("cvescout.domain_scanner.collect_dns")
    @patch("cvescout.domain_scanner.resolve_public_addresses")
    def test_domain_scan_persists_findings_without_cookie_values(self, resolve, collect_dns, probe_https_mock, probe_http_mock):
        resolve.return_value = ["93.184.216.34"]
        collect_dns.return_value = {"A": ["93.184.216.34"], "CNAME": [], "NS": [], "MX": [], "TXT": [], "DMARC": []}
        probe_https_mock.return_value = {
            "ok": True,
            "address": "93.184.216.34",
            "tls_version": "TLSv1.3",
            "certificate_expires": "",
            "headers": {
                "server": "cloudflare",
                "cf-ray": "abc",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
            "set_cookies": ["session=super-secret; Secure; HttpOnly"],
        }
        probe_http_mock.return_value = {
            "ok": True,
            "status": 301,
            "headers": {"location": "https://app.example.com/"},
            "set_cookies": [],
        }
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,created_at) VALUES(?,?)",
                ("app.example.com", now()),
            ).lastrowid
            db.commit()
            total, new_findings = scan_domain(domain_id)
            self.assertEqual(total, 1)
            self.assertEqual(new_findings, [])  # repeat scan of an unchanged site reports nothing new
            domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
            stored = json.loads(domain["tls_summary"])
            self.assertEqual(domain["provider"], "Cloudflare")
            self.assertEqual(domain["status"], "ok")
            self.assertEqual(stored["set_cookies"], ["session"])
            self.assertNotIn("super-secret", domain["tls_summary"])

    def test_origin_list_validation(self):
        self.assertEqual(
            normalize_origin_ips("93.184.216.34, 2001:4860:4860::8888 93.184.216.34"),
            ["93.184.216.34", "2001:4860:4860::8888"],
        )
        with self.assertRaises(ProviderCheckError):
            normalize_origin_ips("192.168.1.10")
        with self.assertRaises(ProviderCheckError):
            normalize_origin_ips("not-an-ip")
        with self.assertRaises(ProviderCheckError):
            normalize_origin_ips("93.184.216.34," * 5)

    @patch("cvescout.provider_checks.probe_http")
    @patch("cvescout.provider_checks.probe_https")
    def test_origin_check_reports_each_candidate_without_returning_ips(self, probe_https_mock, probe_http_mock):
        probe_https_mock.side_effect = [
            {"ok": True, "status": 200, "headers": {"server": "nginx"}, "body_sha256": "same", "certificate_trusted": False},
            {"ok": False},
            {"ok": False},
        ]
        probe_http_mock.side_effect = [{"ok": False}, {"ok": False}]
        edge_https = {"status": 200, "headers": {"server": "cloudflare"}, "body_sha256": "same"}
        result, summary, details = check_origin("app.example.com", "93.184.216.34, 93.184.216.35", edge_https, {}, "2026-10-29T10:00:00+00:00")
        self.assertEqual(result, "reachable")
        self.assertIn("1 of 2 supplied origins", summary)
        self.assertIn("edge data recorded", summary)
        self.assertTrue(details["candidates"][0]["https"]["matches_edge_body"])
        self.assertFalse(details["candidates"][1]["https"]["reachable"])
        self.assertFalse(details["candidates"][1]["http"]["reachable"])
        stored = json.dumps(details)
        self.assertNotIn("93.184.216.34", stored)
        self.assertNotIn("93.184.216.35", stored)

    @patch("cvescout.provider_checks.probe_http")
    @patch("cvescout.provider_checks.probe_https")
    def test_origin_check_with_no_response_is_reported_per_candidate(self, probe_https_mock, probe_http_mock):
        probe_https_mock.return_value = {"ok": False}
        probe_http_mock.return_value = {"ok": False}
        result, summary, details = check_origin("app.example.com", "93.184.216.34", {}, {})
        self.assertEqual(result, "not_reachable")
        self.assertIn("None of the 1 supplied origins", summary)
        self.assertEqual(details["tested"], 1)

    @patch("cvescout.cloudflare_checks.urllib.request.build_opener")
    def test_cloudflare_optional_request_returns_none_on_403(self, build_opener):
        build_opener.return_value.open.side_effect = urllib.error.HTTPError(
            "https://api.cloudflare.com/client/v4/zones/z/rulesets", 403, "Forbidden", {}, None
        )
        with self.app.app_context():
            self.assertIsNone(cloudflare_checks._api("zones/z/rulesets", optional=True))
            with self.assertRaises(CloudflareCheckError):
                cloudflare_checks._api("zones/z/rulesets")

    @patch("cvescout.cloudflare_checks.urllib.request.build_opener")
    def test_cloudflare_rejects_malformed_json(self, build_opener):
        build_opener.return_value.open.return_value = io.BytesIO(b"<html>not json</html>")
        with self.app.app_context(), self.assertRaisesRegex(CloudflareCheckError, "request failed"):
            cloudflare_checks._api("zones")

    @patch("cvescout.cloudflare_checks.urllib.request.build_opener")
    def test_cloudflare_reports_api_error_message(self, build_opener):
        build_opener.return_value.open.return_value = io.BytesIO(
            b'{"success":false,"errors":[{"message":"Invalid token"}]}'
        )
        with self.app.app_context(), self.assertRaisesRegex(CloudflareCheckError, "Invalid token"):
            cloudflare_checks._api("zones")

    @patch("cvescout.cloudflare_checks.urllib.request.build_opener")
    def test_cloudflare_api_uses_fixed_endpoint_and_bearer_token(self, build_opener):
        build_opener.return_value.open.return_value = io.BytesIO(b'{"success":true,"result":[]}')
        with self.app.app_context():
            self.assertEqual(cloudflare_checks._api("zones", {"name": "example.com"}), [])
        request = build_opener.return_value.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://api.cloudflare.com/client/v4/zones?"))
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    @patch("cvescout.cloudflare_checks._api")
    def test_cloudflare_check_reports_proxy_and_tls_settings(self, api):
        def response(path, params=None, optional=False):
            if path == "zones" and params["name"] == "app.example.com":
                return []
            if path == "zones":
                return [{"id": "zone-1", "name": "example.com"}]
            if path.endswith("dns_records"):
                return [{"type": "A", "proxied": False}]
            if path.endswith("settings"):
                return [
                    {"id": "ssl", "value": "flexible"},
                    {"id": "always_use_https", "value": "off"},
                    {"id": "min_tls_version", "value": "1.0"},
                    {"id": "tls_1_3", "value": "off"},
                ]
            if path.endswith("dnssec"):
                return {"status": "disabled"}
            if "rulesets/phases" in path:
                return None
            self.fail(f"Unexpected Cloudflare path: {path}")

        api.side_effect = response
        with self.app.app_context():
            result, summary, details = check_cloudflare("app.example.com")
        checks = {check["key"]: check for check in details["checks"]}
        self.assertEqual(result, "fail")
        self.assertIn("high-risk", summary)
        self.assertEqual(checks["dns.proxy"]["status"], "fail")
        self.assertEqual(checks["ssl.mode"]["severity"], "high")
        self.assertEqual(details["zone"], "example.com")
        self.assertNotIn("test-token", json.dumps(details))

    def test_domain_page_renders_provider_check_history(self):
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,provider,status,created_at) VALUES(?,?,?,?)",
                ("app.example.com", "Cloudflare", "warning", now()),
            ).lastrowid
            db.execute(
                "INSERT INTO domain_checks(domain_id,kind,username,status,result,summary,details,started_at,finished_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    domain_id,
                    "origin",
                    "admin",
                    "completed",
                    "reachable",
                    "Origin answered directly.",
                    json.dumps({"https": {"reachable": True}, "http": {"reachable": False}}),
                    now(),
                    now(),
                ),
            )
            db.commit()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        html = client.get(f"/domains/{domain_id}").get_data(as_text=True)
        self.assertIn("Known-origin reachability", html)
        self.assertIn("Check Cloudflare", html)
        self.assertIn("Origin answered directly", html)

    @patch("cvescout.jobs._pool")
    def test_origin_ip_is_not_persisted_when_job_is_queued(self, submit):
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,created_at,last_scanned,addresses) VALUES(?,?,?,?)",
                ("app.example.com", now(), now(), '["10.0.0.1"]'),
            ).lastrowid
            db.commit()
            submit_origin_check(self.app, domain_id, "93.184.216.34", "admin")
            rows = [
                *db.execute("SELECT * FROM jobs").fetchall(),
                *db.execute("SELECT * FROM domain_checks").fetchall(),
                *db.execute("SELECT * FROM events").fetchall(),
            ]
            stored = " ".join(str(value) for row in rows for value in row)
        self.assertNotIn("93.184.216.34", stored)
        submit.assert_called_once()

    @patch("cvescout.views.domains.submit_origin_check")
    def test_origin_route_requires_authorization_confirmation(self, submit):
        with self.app.app_context():
            db = get_db()
            domain_id = db.execute(
                "INSERT INTO domains(name,created_at) VALUES(?,?)",
                ("app.example.com", now()),
            ).lastrowid
            db.commit()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        client.post(
            f"/domains/{domain_id}/check-origin",
            data={"csrf_token": "token", "origin_ip": "93.184.216.34"},
        )
        submit.assert_not_called()
        client.post(
            f"/domains/{domain_id}/check-origin",
            data={
                "csrf_token": "token",
                "origin_ip": "93.184.216.34",
                "authorized": "yes",
            },
        )
        submit.assert_called_once()

    def test_domain_add_requires_authorization_confirmation(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        response = client.post(
            "/domains",
            data={"csrf_token": "token", "name": "app.example.com"},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM domains").fetchone()[0], 0)
        client.post(
            "/domains",
            data={"csrf_token": "token", "name": "APP.example.com.", "authorized": "yes"},
        )
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT name FROM domains").fetchone()[0], "app.example.com")


if __name__ == "__main__":
    unittest.main()

"""Tests for the improved domain edge analysis: TLS error classification, weak
ciphers, disclosure headers, SameSite, redirect targets, SPF limits, DNS
signals, security.txt, and the extra Cloudflare settings checks."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cvescout import create_app
from cvescout.cloudflare_checks import _settings_checks
from cvescout.domain_findings import (
    _certificate_findings,
    _cookie_findings,
    _dns_findings,
    _email_findings,
    _header_findings,
    _security_txt_findings,
    _transport_findings,
    analyze_domain,
)
from cvescout.domain_scanner import _stored_probe, probe_security_txt


def _keys(findings: list[dict]) -> set[str]:
    return {finding["finding_key"] for finding in findings}


class TlsFindingTests(unittest.TestCase):
    def test_failure_classification(self):
        cases = {
            "hostname mismatch": "tls.hostname_mismatch",
            "certificate has expired": "tls.certificate_dates",
            "self-signed certificate": "tls.untrusted",
            "unable to get local issuer certificate": "tls.untrusted",
            "connection refused": "tls.unavailable",
        }
        for error, key in cases.items():
            findings = _certificate_findings({"ok": False, "error": f"93.184.216.34: {error}"})
            self.assertIn(key, _keys(findings), error)
            self.assertEqual(findings[0]["severity"], "high")

    def test_weak_ciphers(self):
        base = {"ok": True, "tls_version": "TLSv1.2", "certificate_expires": ""}
        high = _certificate_findings({**base, "cipher": "ECDHE-RSA-RC4-SHA"})
        self.assertIn("tls.weak_cipher", _keys(high))
        self.assertEqual(next(f for f in high if f["finding_key"] == "tls.weak_cipher")["severity"], "high")
        medium = _certificate_findings({**base, "cipher": "DES-CBC3-SHA"})
        self.assertEqual(next(f for f in medium if f["finding_key"] == "tls.weak_cipher")["severity"], "medium")
        good = _certificate_findings({**base, "cipher": "TLS_AES_128_GCM_SHA256"})
        self.assertNotIn("tls.weak_cipher", _keys(good))

    def test_expired_certificate_wording(self):
        expired = (datetime.now(UTC) - timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
        findings = _certificate_findings({"ok": True, "tls_version": "TLSv1.3", "certificate_expires": expired})
        finding = next(f for f in findings if f["finding_key"] == "tls.certificate_expiry")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("expired", finding["title"].lower())


class HeaderAndCookieTests(unittest.TestCase):
    def test_x_powered_by_version_disclosure(self):
        https = {"ok": True, "headers": {"x-powered-by": "PHP/7.4.3"}}
        self.assertIn("http.powered_by_version", _keys(_header_findings(https)))

    def test_samesite_missing(self):
        https = {"ok": True, "set_cookies": ["session=abc; Secure; HttpOnly"]}
        self.assertIn("cookie.session.samesite_missing", _keys(_cookie_findings(https)))
        https = {"ok": True, "set_cookies": ["session=abc; Secure; HttpOnly; SameSite=Lax"]}
        self.assertNotIn("cookie.session.samesite_missing", _keys(_cookie_findings(https)))


class TransportTests(unittest.TestCase):
    def test_redirect_to_other_hostname_is_flagged(self):
        http = {"ok": True, "status": 301, "headers": {"location": "https://other.example/"}}
        findings = _transport_findings(http, "app.example.com")
        self.assertIn("http.redirect_offsite", _keys(findings))

    def test_redirect_to_same_hostname_is_fine(self):
        http = {"ok": True, "status": 301, "headers": {"location": "https://app.example.com/"}}
        self.assertEqual(_transport_findings(http, "app.example.com"), [])


class EmailAndDnsTests(unittest.TestCase):
    def test_spf_lookup_limit(self):
        many = "v=spf1 " + " ".join(f"include:_spf{i}.example.com" for i in range(11)) + " ~all"
        records = {"MX": ["10 mail.example.com"], "TXT": [many], "DMARC": []}
        self.assertIn("email.spf_too_many_lookups", _keys(_email_findings(records)))
        few = "v=spf1 " + " ".join(f"include:_spf{i}.example.com" for i in range(10)) + " ~all"
        records = {"MX": ["10 mail.example.com"], "TXT": [few], "DMARC": []}
        self.assertNotIn("email.spf_too_many_lookups", _keys(_email_findings(records)))

    def test_dns_positive_signals_only(self):
        self.assertEqual(_dns_findings({}), [])
        findings = _dns_findings({"CAA": ['0 issue "letsencrypt.org"'], "DS": ["12345 8 2 abc"]})
        self.assertEqual(_keys(findings), {"dns.caa_present", "dns.dnssec_present"})


class SecurityTxtTests(unittest.TestCase):
    def test_present_and_missing(self):
        present = {"ok": True, "status": 200, "body_text": "Contact: mailto:security@example.com\nExpires: 2027-01-01"}
        self.assertIn("disclosure.security_txt", _keys(_security_txt_findings(present)))
        missing = {"ok": True, "status": 404, "body_text": "not found"}
        self.assertIn("disclosure.security_txt_missing", _keys(_security_txt_findings(missing)))
        self.assertEqual(_security_txt_findings(None), [])
        self.assertEqual(_security_txt_findings({"ok": False}), [])

    def test_stored_probe_strips_captured_text(self):
        stored = _stored_probe({"ok": True, "body_text": "Contact: x", "set_cookies": ["a=secret; Secure"]})
        self.assertNotIn("body_text", stored)
        self.assertEqual(stored["set_cookies"], ["a"])


class ProbeSecurityTxtTests(unittest.TestCase):
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

    def test_https_preferred_with_http_fallback(self):
        with (
            patch("cvescout.domain_scanner.probe_https", return_value={"ok": True, "status": 200}) as https,
            patch("cvescout.domain_scanner.probe_http") as http,
            self.app.app_context(),
        ):
            result = probe_security_txt("app.example.com", ["93.184.216.34"], True)
        self.assertTrue(result["ok"])
        https.assert_called_once()
        http.assert_not_called()
        self.assertEqual(https.call_args.kwargs["path"], "/.well-known/security.txt")

        with (
            patch("cvescout.domain_scanner.probe_https", return_value={"ok": False}) as https,
            patch("cvescout.domain_scanner.probe_http", return_value={"ok": True, "status": 200}) as http,
            self.app.app_context(),
        ):
            result = probe_security_txt("app.example.com", ["93.184.216.34"], True)
        self.assertTrue(result["ok"])
        http.assert_called_once()


class CloudflareSettingsTests(unittest.TestCase):
    def test_security_level_and_browser_check(self):
        settings = {
            "ssl": "strict",
            "always_use_https": "on",
            "min_tls_version": "1.2",
            "tls_1_3": "on",
            "security_level": "off",
            "browser_check": "off",
        }
        checks = {check["key"]: check for check in _settings_checks(settings)}
        self.assertEqual(checks["security.level"]["status"], "fail")
        self.assertEqual(checks["browser.check"]["status"], "review")
        settings["security_level"] = "medium"
        settings["browser_check"] = "on"
        checks = {check["key"]: check for check in _settings_checks(settings)}
        self.assertEqual(checks["security.level"]["status"], "pass")
        self.assertEqual(checks["browser.check"]["status"], "pass")


class AnalyzeIntegrationTests(unittest.TestCase):
    def test_name_and_security_txt_flow_through(self):
        records = {"CNAME": [], "NS": [], "MX": [], "TXT": [], "DMARC": []}
        https = {"ok": True, "tls_version": "TLSv1.3", "headers": {}, "set_cookies": []}
        http = {"ok": True, "status": 301, "headers": {"location": "https://elsewhere.example/"}}
        security_txt = {"ok": True, "status": 200, "body_text": "Contact: mailto:x@example.com"}
        _provider, findings = analyze_domain(records, https, http, security_txt=security_txt, name="app.example.com")
        keys = _keys(findings)
        self.assertIn("http.redirect_offsite", keys)
        self.assertIn("disclosure.security_txt", keys)


if __name__ == "__main__":
    unittest.main()

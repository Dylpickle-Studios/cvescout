from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from cvescout import create_app, notify
from cvescout.db import get_db, now
from cvescout.jobs import _set_job


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": str(Path(self.tempdir.name) / "test.sqlite3"),
                "NETWORKS": [],
                "NOTIFY_TIMEOUT": 1,
            }
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _config(self, **channels):
        config = {name: dict(values) for name, values in notify.DEFAULTS.items()}
        for name, values in channels.items():
            config[name].update(values)
        return config

    def _client(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "admin"
            session["csrf_token"] = "token"
        return client

    def test_defaults_are_disabled_and_empty(self):
        with self.app.app_context():
            config = notify.load()
        self.assertEqual(set(config), set(notify.CHANNELS))
        self.assertFalse(any(channel["enabled"] for channel in config.values()))

    @patch("cvescout.notify._post")
    def test_enabled_channels_are_skipped_when_disabled(self, post):
        with self.app.app_context():
            notify.save(self._config(webhook={"enabled": False, "url": "https://example.com/hook"}))
            self.assertEqual(notify.notify("title", "body"), {})
        post.assert_not_called()

    @patch("cvescout.notify._post")
    def test_webhook_payload(self, post):
        with self.app.app_context():
            notify.save(self._config(webhook={"enabled": True, "url": "https://example.com/hook"}))
            self.assertEqual(notify.notify("Scan failed", "nmap missing", "high"), {})
        url, body, headers = post.call_args.args[:3]
        self.assertEqual(url, "https://example.com/hook")
        self.assertEqual(json.loads(body), {"source": "cve-scout", "title": "Scan failed", "message": "nmap missing", "priority": "high"})
        self.assertEqual(headers["Content-Type"], "application/json")

    @patch("cvescout.notify._post")
    def test_ntfy_uses_topic_url_and_headers(self, post):
        with self.app.app_context():
            notify.save(self._config(ntfy={"enabled": True, "url": "https://ntfy.sh/cvescout", "token": "tk"}))
            notify.notify("Test", "hello", "high")
        url, body, headers = post.call_args.args[:3]
        self.assertEqual(url, "https://ntfy.sh/cvescout")
        self.assertEqual(body, b"hello")
        self.assertEqual(headers["Priority"], "4")
        self.assertEqual(headers["Authorization"], "Bearer tk")

    @patch("cvescout.notify._post")
    def test_gotify_appends_token_query_and_priority(self, post):
        with self.app.app_context():
            notify.save(self._config(gotify={"enabled": True, "url": "https://gotify.example.com/", "token": "app-token"}))
            notify.notify("Test", "hello", "high")
        url, body, _headers = post.call_args.args[:3]
        self.assertTrue(url.startswith("https://gotify.example.com/message?token=app-token"))
        self.assertEqual(json.loads(body)["priority"], 8)

    @patch("cvescout.notify._post")
    def test_email_payload_splits_recipients(self, post):
        with self.app.app_context():
            notify.save(
                self._config(
                    email={
                        "enabled": True,
                        "url": "https://api.example.com/emails",
                        "token": "api-key",
                        "from": "cvescout@example.com",
                        "to": "a@example.com, b@example.com",
                    }
                )
            )
            notify.notify("Subject", "Body")
        _url, body, headers = post.call_args.args[:3]
        payload = json.loads(body)
        self.assertEqual(payload["to"], ["a@example.com", "b@example.com"])
        self.assertEqual(payload["subject"], "Subject")
        self.assertEqual(headers["Authorization"], "Bearer api-key")

    @patch("cvescout.notify._post")
    def test_failures_are_reported_and_logged_without_tokens(self, post):
        post.side_effect = notify.NotifyError("HTTP 401 from https://gotify.example.com/message?token=app-token")
        with self.app.app_context():
            notify.save(self._config(gotify={"enabled": True, "url": "https://gotify.example.com", "token": "app-token"}))
            failures = notify.notify("Test", "hello")
            events = [row["message"] for row in get_db().execute("SELECT message FROM events WHERE action='notify.failed'")]
        self.assertIn("gotify", failures)
        self.assertNotIn("app-token", json.dumps(failures))
        self.assertNotIn("app-token", " ".join(events))

    def test_validation_rejects_bad_urls_and_missing_fields(self):
        errors = notify.validate(
            self._config(
                webhook={"enabled": True, "url": "ftp://example.com/hook"},
                gotify={"enabled": True, "url": "https://gotify.example.com"},
            )
        )
        joined = " ".join(errors)
        self.assertIn("webhook: url must start", joined)
        self.assertIn("gotify: token is required", joined)

    def test_blank_secret_keeps_the_stored_value(self):
        current = self._config(gotify={"enabled": True, "url": "https://gotify.example.com", "token": "stored"})
        form = {"gotify.enabled": "yes", "gotify.url": "https://gotify.example.com", "gotify.token": ""}
        config = notify.from_form(form, current)
        self.assertEqual(config["gotify"]["token"], "stored")

    @patch("cvescout.notify._post")
    def test_settings_page_saves_and_never_renders_secrets(self, post):
        client = self._client()
        posted = client.post(
            "/settings",
            data={
                "csrf_token": "token",
                "ntfy.enabled": "yes",
                "ntfy.url": "https://ntfy.sh/cvescout",
                "ntfy.token": "super-secret-token",
            },
        )
        self.assertEqual(posted.status_code, 302)
        page = client.get("/settings").get_data(as_text=True)
        self.assertIn("https://ntfy.sh/cvescout", page)
        self.assertNotIn("super-secret-token", page)
        self.assertIn("saved, leave blank to keep", page)

    def test_settings_page_rejects_invalid_url_without_saving(self):
        client = self._client()
        response = client.post(
            "/settings",
            data={"csrf_token": "token", "ntfy.enabled": "yes", "ntfy.url": "not-a-url"},
            follow_redirects=True,
        )
        self.assertIn("must start with http", response.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM settings").fetchone()[0], 0)

    @patch("cvescout.notify._post")
    def test_test_button_reports_delivery(self, post):
        client = self._client()
        client.post("/settings", data={"csrf_token": "token", "webhook.enabled": "yes", "webhook.url": "https://example.com/hook"})
        ok = client.post("/settings/test", data={"csrf_token": "token"}, follow_redirects=True).get_data(as_text=True)
        self.assertIn("Test notification accepted", ok)
        post.side_effect = notify.NotifyError("HTTP 500")
        failed = client.post("/settings/test", data={"csrf_token": "token"}, follow_redirects=True).get_data(as_text=True)
        self.assertIn("webhook: HTTP 500", failed)

    @patch("cvescout.notify._post")
    def test_job_failure_sends_notification(self, post):
        with self.app.app_context():
            notify.save(self._config(webhook={"enabled": True, "url": "https://example.com/hook"}))
            db = get_db()
            job_id = db.execute(
                "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
                ("ports", "", "admin", "running", now()),
            ).lastrowid
            db.commit()
            _set_job(job_id, "failed", "nmap is not installed")
        self.assertTrue(post.called)
        body = json.loads(post.call_args.args[1])
        self.assertIn("ports failed", body["title"])
        self.assertIn("nmap is not installed", body["message"])

    @patch("cvescout.notify._post")
    def test_notification_failure_does_not_break_job_state(self, post):
        post.side_effect = OSError("network down")
        with self.app.app_context():
            notify.save(self._config(webhook={"enabled": True, "url": "https://example.com/hook"}))
            db = get_db()
            job_id = db.execute(
                "INSERT INTO jobs(kind,target,username,status,created_at) VALUES(?,?,?,?,?)",
                ("ports", "", "admin", "running", now()),
            ).lastrowid
            db.commit()
            _set_job(job_id, "failed", "boom")
            status = db.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
        self.assertEqual(status, "failed")

    @patch("cvescout.notify.urllib.request.build_opener")
    def test_http_error_scrubs_token_from_message(self, build_opener):
        build_opener.return_value.open.side_effect = urllib.error.HTTPError(
            "https://gotify.example.com/message?token=app-token", 401, "Unauthorized", {}, None
        )
        with self.app.app_context(), self.assertRaises(notify.NotifyError) as caught:
            notify._post("https://gotify.example.com/message?token=app-token", b"{}", {}, ("app-token",))
        self.assertNotIn("app-token", str(caught.exception))
        self.assertIn("<redacted>", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

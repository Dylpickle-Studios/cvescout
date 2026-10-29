from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash

from cvescout import create_app
from cvescout.db import get_db, now


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE": str(Path(self.tempdir.name) / "test.sqlite3"), "NETWORKS": []})
        with self.app.app_context():
            db = get_db()
            db.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)", ("admin", generate_password_hash("correct horse"), now()))
            db.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def _csrf(self) -> str:
        html = self.client.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def test_login_and_csrf(self):
        response = self.client.post("/login", data={"csrf_token": self._csrf(), "username": "admin", "password": "correct horse"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.post("/scans/network", data={}).status_code, 400)

    def test_bad_password_is_rejected(self):
        response = self.client.post("/login", data={"csrf_token": self._csrf(), "username": "admin", "password": "wrong"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvescout import create_app, platform
from cvescout.cli import UNIT_PLACEHOLDERS


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_auto_profile_thresholds(self):
        self.assertEqual(platform._detected_name(1, 500)[0], "minimal")
        self.assertEqual(platform._detected_name(2, 1000)[0], "balanced")
        self.assertEqual(platform._detected_name(4, 8000)[0], "fast")
        # A Pi Zero with lots of reported cores still has too little RAM for two Nmap processes.
        self.assertEqual(platform._detected_name(4, 512)[0], "minimal")

    def test_pi_zero_is_never_given_parallel_workers(self):
        with patch.object(platform, "hardware", return_value={"model": "Raspberry Pi Zero 2 W Rev 1.0", "cores": 4, "ram_mb": 430, "raspberry_pi": True}), patch.dict(os.environ, {}, clear=False):
            profile = platform.choose()
        self.assertEqual(profile.name, "minimal")
        self.assertEqual(profile.workers, 1)
        self.assertIn("Raspberry Pi Zero", profile.reason)

    def test_explicit_profile_wins(self):
        with patch.dict(os.environ, {"CVESCOUT_PROFILE": "minimal"}, clear=False):
            profile = platform.choose()
        self.assertEqual(profile.name, "minimal")
        self.assertEqual(profile.timing, "-T3")
        self.assertIn("CVESCOUT_PROFILE=minimal", profile.reason)

    def test_unknown_profile_falls_back_to_detection(self):
        with patch.dict(os.environ, {"CVESCOUT_PROFILE": "ludicrous"}, clear=False):
            profile = platform.choose()
        self.assertIn(profile.name, platform.PROFILES)

    def test_worker_and_timing_overrides(self):
        with patch.dict(
            os.environ,
            {"CVESCOUT_PROFILE": "balanced", "CVESCOUT_WORKERS": "1", "CVESCOUT_NMAP_TIMING": "-T2"},
            clear=False,
        ):
            profile = platform.choose()
        self.assertEqual((profile.workers, profile.timing), (1, "-T2"))

    def test_app_config_uses_the_profile(self):
        with patch.dict(os.environ, {"CVESCOUT_PROFILE": "minimal", "CVESCOUT_PORTS": ""}, clear=False):
            os.environ.pop("CVESCOUT_PORTS", None)
            app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test",
                    "DATABASE": str(Path(self.tempdir.name) / "db.sqlite3"),
                    "NETWORKS": [],
                }
            )
        self.assertEqual(app.config["WORKERS"], 1)
        self.assertEqual(app.config["NMAP_TIMING"], "-T3")
        self.assertEqual(app.config["PORTS"], "1-1024,8080,8443")
        self.assertEqual(app.config["PROFILE"].name, "minimal")

    def test_hardware_report_has_expected_keys(self):
        detected = platform.hardware()
        self.assertEqual(set(detected), {"model", "cores", "ram_mb", "raspberry_pi"})
        self.assertGreaterEqual(detected["cores"], 1)


class InstallUnitsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.target = Path(self.tempdir.name) / "units"
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

    def test_units_are_written_with_prefix_and_user_substituted(self):
        result = self.app.test_cli_runner().invoke(
            self.app.cli,
            ["install-units", "--target", str(self.target), "--prefix", "/srv/cvescout", "--user", "scout"],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        names = sorted(path.name for path in self.target.iterdir())
        self.assertEqual(names, ["cvescout-scan.service", "cvescout-scan.timer", "cvescout.service"])
        unit = (self.target / "cvescout.service").read_text()
        self.assertIn("WorkingDirectory=/srv/cvescout", unit)
        self.assertIn("User=scout", unit)
        self.assertIn("ReadWritePaths=/srv/cvescout/instance", unit)
        self.assertNotIn("__PREFIX__", unit)
        self.assertNotIn("__APP_USER__", unit)

    def test_every_placeholder_is_replaced_by_defaults(self):
        result = self.app.test_cli_runner().invoke(self.app.cli, ["install-units", "--target", str(self.target)])
        self.assertEqual(result.exit_code, 0, result.output)
        for path in self.target.iterdir():
            text = path.read_text()
            for placeholder in UNIT_PLACEHOLDERS:
                self.assertNotIn(placeholder, text, path.name)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

TESTS_DIR = pathlib.Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import test_client_recovery_state  # noqa: F401 - installs import stubs when optional deps are absent

import app  # type: ignore


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config.yaml"


class DnsModeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        app._dns_mode_warning_logged = False

    def test_config_yaml_exposes_no_dns_mode_option(self) -> None:
        # dns_mode is intentionally not user-configurable; the runtime default
        # is "off" (see test_missing_dns_mode_normalizes_to_off).
        config = CONFIG_PATH.read_text(encoding="utf-8")
        self.assertNotIn("dns_mode", config)
        self.assertNotIn("auto_dns", config)

    def test_missing_dns_mode_normalizes_to_off(self) -> None:
        self.assertEqual(app.normalize_dns_mode(None), "off")
        self.assertEqual(app.load_options()["dns_mode"], "off")

    def test_boolean_false_normalizes_to_off(self) -> None:
        self.assertEqual(app.normalize_dns_mode(False), "off")

    def test_off_normalizes_to_off(self) -> None:
        self.assertEqual(app.normalize_dns_mode("off"), "off")

    def test_on_normalizes_to_on(self) -> None:
        self.assertEqual(app.normalize_dns_mode("on"), "on")

    def test_unknown_dns_mode_normalizes_to_off(self) -> None:
        self.assertEqual(app.normalize_dns_mode("maybe"), "off")

    def test_stale_auto_dns_alone_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "options.json"
            path.write_text(json.dumps({"auto_dns": "on"}), encoding="utf-8")
            with patch.object(app, "OPTIONS_PATH", path):
                self.assertEqual(app.load_options()["dns_mode"], "off")
            self.assertFalse(app.validate_dns_mode_options_file(path))

    def test_dns_mode_wins_over_stale_auto_dns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "options.json"
            path.write_text(json.dumps({"dns_mode": "on", "auto_dns": "off"}), encoding="utf-8")
            with patch.object(app, "OPTIONS_PATH", path):
                self.assertEqual(app.load_options()["dns_mode"], "on")

    def test_dns_mode_on_produces_non_blocking_warning(self) -> None:
        with self.assertLogs("hometunnel", level="WARNING") as caught:
            warned = app.warn_if_dns_mode_on({"dns_mode": "on"})
        self.assertTrue(warned)
        self.assertIn(app.DNS_MODE_ON_WARNING, "\n".join(caught.output))

    def test_options_file_check_warns_and_continues_when_dns_mode_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "options.json"
            path.write_text(json.dumps({"dns_mode": "on"}), encoding="utf-8")
            with self.assertLogs("hometunnel", level="WARNING") as caught:
                warned = app.validate_dns_mode_options_file(path)
        self.assertTrue(warned)
        self.assertIn(app.DNS_MODE_ON_WARNING, "\n".join(caught.output))

    def test_dns_mode_off_adds_disable_dns_to_netbird_up(self) -> None:
        args = self._netbird_up_args({"dns_mode": "off"})
        self.assertIn("--disable-dns", args)

    def test_dns_mode_on_does_not_add_disable_dns_to_netbird_up(self) -> None:
        args = self._netbird_up_args({"dns_mode": "on"})
        self.assertNotIn("--disable-dns", args)

    def test_unknown_dns_mode_adds_disable_dns_to_netbird_up(self) -> None:
        args = self._netbird_up_args({"dns_mode": "maybe"})
        self.assertIn("--disable-dns", args)

    def _netbird_up_args(self, options: dict) -> list[str]:
        state = {
            "management_url": "https://mgmt.example",
            "setup_key": "setup-key",
            "peer_name": "peer",
            "binding": {"status": "valid", "expected_netbird_label": "ht-device-device-1"},
        }
        captured: list[str] = []

        def fake_run_command(args: list[str], timeout_seconds: int = 20) -> tuple[int, str, str]:
            captured.extend(args)
            return 0, "", ""

        merged_options = {"log_level": "info", **options}
        with patch.object(app, "netbird_binary_path", return_value="/usr/bin/netbird"), patch.object(
            app, "run_command", side_effect=fake_run_command
        ), patch.object(app, "read_resolver_diagnostics", return_value={"nameservers": []}), patch.object(
            app, "update_state"
        ), patch.object(app, "chmod_if_exists"):
            ok, message = app.netbird_up(state, merged_options)
        self.assertTrue(ok, message)
        return captured


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
import io
import json
import logging
import pathlib
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

TESTS_DIR = pathlib.Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import test_client_recovery_state  # noqa: F401 - installs import stubs when optional deps are absent

import app  # type: ignore


ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "rootfs" / "opt" / "hometunnel" / "app.py"
REQUIREMENTS_PATH = ROOT / "rootfs" / "opt" / "hometunnel" / "requirements.txt"


def response_payload(response) -> dict:
    body = getattr(response, "body", None)
    if body is not None:
        return json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    args = getattr(response, "args", ())
    return args[0] if args else {}


def response_status(response) -> int:
    return int(getattr(response, "status_code", getattr(response, "kwargs", {}).get("status_code", 200)))


class _Request:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    async def json(self) -> dict:
        return self._payload


class _Thread:
    started = 0

    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def start(self) -> None:
        type(self).started += 1


class UiSecurityTests(unittest.TestCase):
    def test_status_values_are_html_escaped(self) -> None:
        js = app.APP_JS
        self.assertIn("function escapeHtml(", js)
        self.assertIn("${escapeHtml(k)}", js)
        self.assertIn("escapeHtml(v)", js)
        self.assertNotIn("<dd>${v ?? ", js)

    def test_ingress_and_loopback_clients_are_trusted(self) -> None:
        for host in ("172.30.32.2", "127.0.0.1", "::1", "::ffff:172.30.32.2"):
            self.assertTrue(app.ui_client_is_trusted(host), host)

    def test_lan_and_overlay_clients_are_rejected(self) -> None:
        for host in ("192.168.1.50", "100.94.10.7", "172.30.33.5", "10.0.0.2", "not-an-ip", "", None):
            self.assertFalse(app.ui_client_is_trusted(host), repr(host))

    def test_trusted_clients_env_extends_allowlist(self) -> None:
        import os

        original = app._ui_trusted_networks
        try:
            app._ui_trusted_networks = None
            with patch.dict(os.environ, {"UI_TRUSTED_CLIENTS": "192.168.50.0/24, bogus"}):
                self.assertTrue(app.ui_client_is_trusted("192.168.50.10"))
                self.assertFalse(app.ui_client_is_trusted("192.168.51.10"))
        finally:
            app._ui_trusted_networks = original


class PairingUiStaticTests(unittest.TestCase):
    def test_url_enrollment_method_removed_from_pairing_ui(self) -> None:
        html = app.index()
        self.assertNotIn("Verification URL", html)
        self.assertNotIn('id="verificationUrl"', html)
        self.assertNotIn('id="verificationLink"', html)
        self.assertNotIn('id="openVerificationBtn"', html)
        self.assertNotIn('id="copyVerificationBtn"', html)
        self.assertIn("Open the HomeTunnel app and enter this code.", html)

    def test_copy_code_button_exists_with_status_feedback(self) -> None:
        html = app.index()
        self.assertIn('id="copyCodeBtn"', html)
        self.assertIn(">Copy code<", html)
        self.assertIn('id="codeCopyStatus"', html)

    def test_copy_code_uses_clipboard_fallback_helper(self) -> None:
        js = app.APP_JS
        self.assertIn("await copyTextToClipboard(code);", js)
        self.assertIn('codeCopyStatus.textContent = "Copied";', js)
        self.assertNotIn("navigator.clipboard.writeText(code)", js)

    def test_clipboard_fallback_exists_for_wkwebview(self) -> None:
        js = app.APP_JS
        self.assertIn("navigator.clipboard.writeText(text)", js)
        self.assertIn('document.createElement("textarea")', js)
        self.assertIn('document.execCommand("copy")', js)
        self.assertIn("document.body.removeChild(textarea)", js)
        self.assertIn("Copy failed — copy the code manually", js)

    def test_verification_url_dead_code_removed(self) -> None:
        js = app.APP_JS
        self.assertNotIn("currentVerificationUrl", js)
        self.assertNotIn("normalizeVerificationUrl", js)
        self.assertNotIn("window.location.assign", js)

    def test_active_status_refresh_does_not_restart_approval_poll_timer(self) -> None:
        js = app.APP_JS
        self.assertIn('let pollTimerKey = "";', js)
        self.assertIn("const APPROVAL_POLL_INTERVAL_SECONDS = 5;", js)
        self.assertIn("const pollMs = APPROVAL_POLL_INTERVAL_SECONDS * 1000;", js)
        self.assertIn('const nextPollTimerKey = `${deviceCode || ""}:${pollMs}`;', js)
        self.assertIn("if (pollTimer && pollTimerKey === nextPollTimerKey)", js)
        self.assertIn("startPollTimer(auth.device_code);", js)
        self.assertLess(
            js.index("if (pollTimer && pollTimerKey === nextPollTimerKey)"),
            js.index("stopPollTimer();", js.index("function startPollTimer")),
        )

    def test_status_card_shows_only_important_statuses(self) -> None:
        html = app.index()
        js = app.APP_JS
        self.assertIn('<dl id="status">', html)
        self.assertIn('<details id="advancedDetails">', html)
        self.assertIn('<dl id="statusAdvanced">', html)
        self.assertIn('<dl id="settings">', html)
        self.assertIn('"NetBird connected"', js)
        self.assertIn('"Effective target CIDR"', js)
        self.assertIn("setDl(statusAdvancedEl", js)

    def test_ui_distinguishes_transport_from_portal_trust(self) -> None:
        js = app.APP_JS
        self.assertIn('"portal_trust_degraded"', js)
        self.assertIn("Portal trust degraded", js)
        self.assertIn("Tunnel transport connected", js)
        self.assertIn("Portal trust is reported separately.", js)
        self.assertNotIn("Using secure tunnel", js)

    def test_no_overview_url_generated_for_verification_links(self) -> None:
        self.assertNotIn("/overview", app.APP_JS)
        self.assertNotIn("/overview", app.index())

    def test_pairing_code_ui_does_not_render_secret_fields(self) -> None:
        html = app.index()
        ui_block = html.split("Pairing code", 1)[1].split("Open the HomeTunnel app", 1)[0]
        for secret_name in ("setup_key", "device_token", "binding_token", "signed_binding_token"):
            self.assertNotIn(secret_name, ui_block)

    def test_requirements_do_not_restore_qr_python_dependencies(self) -> None:
        requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8").lower()
        self.assertNotIn("qrcode", requirements)
        self.assertNotIn("qrcode[pil]", requirements)
        self.assertNotIn("pillow", requirements)


class TransportStateTests(unittest.TestCase):
    def _base_state(self) -> dict:
        return {
            "device_id": "dev-1",
            "home_id": "home-1",
            "netbird": {},
            "netbird_peer_id": None,
            "binding": {},
            "netbird_transport_degraded": False,
        }

    def test_transport_ready_accepts_overlay_ip_without_local_peer_id(self) -> None:
        state = self._base_state()
        state["netbird"] = {"connected": True, "peer_id": None, "peer_ip": "100.87.34.152"}
        self.assertTrue(app.transport_ready_from_state(state))

    def test_transport_ready_accepts_portal_peer_id(self) -> None:
        state = self._base_state()
        state["netbird"] = {"connected": True, "peer_id": None, "peer_ip": None}
        state["netbird_peer_id"] = "d9ifbabg0fcc73fi0emg"
        self.assertTrue(app.transport_ready_from_state(state))

    def test_transport_not_ready_when_disconnected(self) -> None:
        state = self._base_state()
        state["netbird"] = {"connected": False, "peer_ip": "100.87.34.152"}
        state["netbird_peer_id"] = "d9ifbabg0fcc73fi0emg"
        self.assertFalse(app.transport_ready_from_state(state))

    def test_display_peer_id_falls_back_to_portal_id(self) -> None:
        state = self._base_state()
        state["netbird"] = {"peer_id": None}
        state["netbird_peer_id"] = "portal-peer-1"
        self.assertEqual(app.display_peer_id_from_state(state), "portal-peer-1")

    def test_healthy_device_reports_connected(self) -> None:
        state = self._base_state()
        state["netbird"] = {"connected": True, "peer_ip": "100.87.34.152"}
        state["netbird_peer_id"] = "portal-peer-1"
        state["binding"] = {"valid": True}
        state["last_heartbeat_at"] = datetime.now(timezone.utc).isoformat()
        state["transport_ready"] = app.transport_ready_from_state(state)
        state["binding_ready"] = app.binding_ready_from_state(state)
        state["paired"] = True
        self.assertEqual(app.derive_pairing_state(state), "connected")

    def test_transport_degraded_flag_forces_error_state(self) -> None:
        state = self._base_state()
        state["netbird"] = {"connected": True, "peer_ip": "100.87.34.152"}
        state["netbird_peer_id"] = "portal-peer-1"
        state["binding"] = {"valid": True}
        state["last_heartbeat_at"] = datetime.now(timezone.utc).isoformat()
        state["transport_ready"] = True
        state["binding_ready"] = True
        state["paired"] = True
        state["netbird_transport_degraded"] = True
        self.assertEqual(app.derive_pairing_state(state), "error")
        status, _detail = app.derive_local_status(state)
        self.assertEqual(status, "netbird_transport_degraded")

    def test_management_connected_detects_degradation(self) -> None:
        healthy = {"management": {"connected": True, "error": ""}}
        self.assertIs(app.extract_netbird_management_connected(healthy), True)
        degraded_flag = {"management": {"connected": False, "error": ""}}
        self.assertIs(app.extract_netbird_management_connected(degraded_flag), False)
        degraded_error = {"management": {"connected": True, "error": "rpc error: code = Internal"}}
        self.assertIs(app.extract_netbird_management_connected(degraded_error), False)
        unknown = {"peers": {}}
        self.assertIsNone(app.extract_netbird_management_connected(unknown))

    def test_management_degraded_marker_in_raw_text(self) -> None:
        self.assertIs(
            app.extract_netbird_management_connected({}, "management transport is up but the sync stream is unhealthy"),
            False,
        )


class SupervisorHostTargetTests(unittest.TestCase):
    def test_parses_address_list(self) -> None:
        payload = {"address": ["192.168.68.151/24"], "gateway": "192.168.68.1"}
        self.assertEqual(app.extract_supervisor_interface_ip(payload), "192.168.68.151")
        self.assertEqual(app.supervisor_interface_cidr(payload), "192.168.68.151/24")

    def test_falls_back_to_legacy_scalar(self) -> None:
        payload = {"ip_address": "192.168.68.151/24"}
        self.assertEqual(app.extract_supervisor_interface_ip(payload), "192.168.68.151")

    def test_missing_address_returns_none(self) -> None:
        self.assertIsNone(app.extract_supervisor_interface_ip({"address": []}))
        self.assertIsNone(app.extract_supervisor_interface_ip({}))

    def test_select_supervisor_host_target_uses_address_list(self) -> None:
        network_info = {
            "interfaces": [
                {
                    "interface": "enp0s1",
                    "primary": True,
                    "enabled": True,
                    "connected": True,
                    "ipv4": {"address": ["192.168.68.151/24"], "gateway": "192.168.68.1"},
                    "ipv6": {},
                }
            ]
        }
        with patch.object(app, "supervisor_request_json", return_value=network_info):
            candidate, error = app.select_supervisor_host_target()
        self.assertIsNone(error)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["host"], "192.168.68.151")
        self.assertEqual(candidate["host_cidr"], "192.168.68.151/24")

    def test_select_supervisor_host_target_missing_ip(self) -> None:
        network_info = {"interfaces": [{"interface": "enp0s1", "enabled": True, "ipv4": {"address": []}}]}
        with patch.object(app, "supervisor_request_json", return_value=network_info):
            candidate, error = app.select_supervisor_host_target()
        self.assertIsNone(candidate)
        self.assertEqual(error, "no_primary_interface_ip")


class NetbirdAgentStatePersistenceTests(unittest.TestCase):
    def test_status_update_preserves_route_written_by_discovery(self) -> None:
        latest_state = {
            "agent_running": True,
            "netbird": {"connected": True, "peer_ip": "100.87.103.25"},
            "route": {
                "target_ip": "192.168.68.159",
                "resolved_target_ip": "192.168.68.159",
                "effective_target_cidr": "192.168.68.159/32",
                "target_source": "supervisor_network",
                "needs_report": True,
            },
        }
        live_status = {
            "connected": True,
            "peer_ip": "100.87.103.25",
            "management_connected": True,
        }
        written: list[dict] = []

        with (
            patch.object(app, "default_state", return_value={}),
            patch.object(app, "read_json_file", return_value=json.loads(json.dumps(latest_state))),
            patch.object(app, "write_json_file", side_effect=lambda _path, value: written.append(json.loads(json.dumps(value)))),
        ):
            result = app.persist_netbird_agent_status(live_status)

        self.assertEqual(result["route"]["target_ip"], "192.168.68.159")
        self.assertEqual(result["route"]["effective_target_cidr"], "192.168.68.159/32")
        self.assertTrue(result["route"]["needs_report"])
        self.assertEqual(result["netbird"], live_status)
        self.assertEqual(written, [result])


class SupervisorCapabilityTests(unittest.TestCase):
    def test_supervisor_request_unwraps_native_api_response(self) -> None:
        response = {
            "result": "ok",
            "data": {"interfaces": [{"interface": "enp0s1"}]},
        }
        with (
            patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "present"}, clear=True),
            patch.object(app, "request_json", return_value=response),
        ):
            payload = app.supervisor_request_json("/network/info")
        self.assertEqual(payload, response["data"])

    def test_supervisor_request_preserves_direct_core_proxy_response(self) -> None:
        response = {"internal_url": "http://192.168.68.151:8123"}
        with (
            patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "present"}, clear=True),
            patch.object(app, "request_json", return_value=response),
        ):
            payload = app.supervisor_request_json("/core/api/config")
        self.assertEqual(payload, response)

    def test_supervisor_request_rejects_error_envelope(self) -> None:
        response = {"result": "error", "message": "network unavailable"}
        with (
            patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "present"}, clear=True),
            patch.object(app, "request_json", return_value=response),
            self.assertRaisesRegex(RuntimeError, "network unavailable"),
        ):
            app.supervisor_request_json("/network/info")

    def test_capability_reports_missing_token_without_exposing_a_value(self) -> None:
        with patch.dict(app.os.environ, {}, clear=True):
            capability = app.supervisor_api_capability()
        self.assertTrue(capability["declared"])
        self.assertFalse(capability["received"])
        self.assertFalse(capability["token_available"])
        self.assertEqual(capability["status"], "token_missing")
        self.assertEqual(
            set(capability),
            {"declared", "received", "token_available", "status"},
        )

    def test_capability_reports_received_token_without_exposing_it(self) -> None:
        with patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "super-secret"}, clear=True):
            capability = app.supervisor_api_capability()
        self.assertTrue(capability["received"])
        self.assertEqual(capability["status"], "available")
        self.assertNotIn("super-secret", json.dumps(capability))


class RouteTargetFailClosedTests(unittest.TestCase):
    def test_missing_supervisor_token_never_evaluates_route_candidates(self) -> None:
        with (
            patch.dict(app.os.environ, {}, clear=True),
            patch.object(app, "select_supervisor_host_target") as supervisor_target,
            patch.object(app, "select_core_config_target") as core_target,
            patch.object(app, "resolve_host_ips") as resolve_host,
        ):
            selected = app.resolve_route_target(
                {"home_assistant_target": "192.168.68.151"},
                {"route": {"target_ip": "192.168.68.141", "target_source_origin": "supervisor_network"}},
            )
        supervisor_target.assert_not_called()
        core_target.assert_not_called()
        resolve_host.assert_not_called()
        self.assertEqual(selected["health_status"], "unresolved")
        self.assertIsNone(selected["target_ip"])
        self.assertIsNone(selected["route_network"])
        self.assertIsNone(selected["effective_target_cidr"])
        self.assertFalse(selected["supervisor_api_authenticated"])
        self.assertIn("supervisor_network:SUPERVISOR_TOKEN missing", selected["target_resolution_errors"])

    def test_supervisor_authentication_failure_discards_trusted_cache(self) -> None:
        auth_error = urllib.error.HTTPError(
            "http://supervisor/network/info", 401, "Unauthorized", {}, None
        )
        with (
            patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "present"}, clear=True),
            patch.object(app, "select_supervisor_host_target", side_effect=auth_error),
            patch.object(app, "select_core_config_target") as core_target,
            patch.object(app, "resolve_host_ips") as resolve_host,
        ):
            selected = app.resolve_route_target(
                {},
                {"route": {"target_ip": "192.168.68.141", "target_source_origin": "supervisor_network"}},
            )
        resolve_host.assert_not_called()
        core_target.assert_not_called()
        self.assertEqual(selected["health_status"], "unresolved")
        self.assertIsNone(selected["target_ip"])
        self.assertFalse(selected["supervisor_api_authenticated"])

    def test_route_resolution_never_uses_homeassistant_local(self) -> None:
        with (
            patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "present"}, clear=True),
            patch.object(app, "select_supervisor_host_target", return_value=(None, "no_primary_interface_ip")),
            patch.object(app, "select_core_config_target", return_value=(None, "core_urls_missing")),
            patch.object(app, "resolve_host_ips") as resolve_host,
        ):
            selected = app.resolve_route_target({}, {"route": {}})
        resolve_host.assert_not_called()
        self.assertEqual(selected["health_status"], "unresolved")
        self.assertIsNone(selected["target_ip"])
        self.assertNotIn("homeassistant_local", json.dumps(selected))

    def test_authoritative_supervisor_target_produces_own_host_route(self) -> None:
        candidate = {
            "host": "192.168.68.151",
            "port": 8123,
            "scheme": "http",
            "target_type": "ipv4",
            "target_hostname": None,
            "host_cidr": "192.168.68.151/24",
        }
        with (
            patch.dict(app.os.environ, {"SUPERVISOR_TOKEN": "present"}, clear=True),
            patch.object(app, "select_supervisor_host_target", return_value=(candidate, None)),
            patch.object(app, "select_core_config_target", return_value=(None, "core_urls_missing")),
            patch.object(app, "resolve_host_ips", return_value=["192.168.68.151"]),
            patch.object(app, "tcp_target_reachable", return_value=(True, None)),
        ):
            selected = app.resolve_route_target({}, {"route": {}})
        self.assertEqual(selected["target_source"], "supervisor_network")
        self.assertEqual(selected["target_ip"], "192.168.68.151")
        self.assertEqual(selected["route_network"], "192.168.68.151/32")
        self.assertTrue(selected["supervisor_api_authenticated"])


class RouteTargetCacheTrustTests(unittest.TestCase):
    def test_poisoned_mdns_cache_rejected(self) -> None:
        # The exact shape from the field: a cached homeassistant.local entry that
        # keeps re-winning as "last_known_good" and pinning the neighbor's IP.
        cached = {
            "target_hostname": "homeassistant.local",
            "target_ip": "192.168.68.141",
            "target_host": "homeassistant.local",
            "target_source": "last_known_good",
        }
        self.assertEqual(app.trusted_cached_route_value(cached), "")

    def test_mdns_origin_ip_rejected(self) -> None:
        cached = {
            "target_ip": "192.168.68.141",
            "target_source": "homeassistant_local",
            "target_source_origin": "homeassistant_local",
        }
        self.assertEqual(app.trusted_cached_route_value(cached), "")

    def test_supervisor_origin_ip_trusted(self) -> None:
        cached = {
            "target_ip": "192.168.68.151",
            "target_source": "last_known_good",
            "target_source_origin": "supervisor_network",
        }
        self.assertEqual(app.trusted_cached_route_value(cached), "192.168.68.151")

    def test_configured_hostname_trusted(self) -> None:
        cached = {
            "target_hostname": "my-ha.lan",
            "target_source_origin": "configured_target",
        }
        self.assertEqual(app.trusted_cached_route_value(cached), "my-ha.lan")


class HaProxyUpstreamResolverTests(unittest.TestCase):
    def _resolver(self, cache_payload: dict | None = None) -> "app.HomeAssistantUpstreamResolver":
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cache_path = pathlib.Path(tmp.name) / "ha_proxy_cache.json"
        if cache_payload is not None:
            cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")
        with patch.object(app, "update_proxy_runtime_state"):
            return app.HomeAssistantUpstreamResolver(cache_path)

    def test_internal_service_probed_before_mdns(self) -> None:
        resolver = self._resolver()
        with patch.object(app, "load_options", return_value={}):
            order = [source for source, _ in resolver._candidate_urls()]
        self.assertIn("homeassistant_service", order)
        self.assertIn("homeassistant_local", order)
        self.assertLess(order.index("homeassistant_service"), order.index("homeassistant_local"))

    def test_rewrite_candidates_keep_mdns_as_last_resort(self) -> None:
        with (
            patch.dict(app.os.environ, {}, clear=True),
            patch.object(app, "load_options", return_value={}),
        ):
            candidates = app.proxy_rewrite_candidate_bases(None)
        self.assertIn("http://homeassistant:8123", candidates)
        self.assertEqual(candidates[-1], "http://homeassistant.local:8123")

    def test_mdns_cache_is_not_loaded(self) -> None:
        resolver = self._resolver({"last_known_good_url": "http://homeassistant.local:8123"})
        self.assertIsNone(resolver._current_url)

    def test_trusted_cache_is_loaded(self) -> None:
        resolver = self._resolver({"last_known_good_url": "http://192.168.68.151:8123"})
        self.assertEqual(resolver._current_url, "http://192.168.68.151:8123")

    def test_mdns_url_is_not_persisted(self) -> None:
        resolver = self._resolver()
        with (
            patch.object(app, "update_proxy_runtime_state"),
            patch.object(app, "ensure_data_dir"),
        ):
            resolver._store_cache("http://homeassistant.local:8123", "homeassistant_local", app.now_iso(), None)
        cached = json.loads(resolver._cache_path.read_text(encoding="utf-8"))
        self.assertIsNone(cached["last_known_good_url"])
        self.assertIsNone(cached["last_known_good_source"])

    def test_non_mdns_url_is_persisted(self) -> None:
        resolver = self._resolver()
        with (
            patch.object(app, "update_proxy_runtime_state"),
            patch.object(app, "ensure_data_dir"),
        ):
            resolver._store_cache("http://homeassistant:8123", "homeassistant_service", app.now_iso(), None)
        cached = json.loads(resolver._cache_path.read_text(encoding="utf-8"))
        self.assertEqual(cached["last_known_good_url"], "http://homeassistant:8123")


class NetbirdStatusTextFallbackTests(unittest.TestCase):
    def _collect_with_text_output(self, text: str) -> dict:
        app._netbird_status_cache["value"] = None
        app._netbird_status_cache["at"] = 0.0
        calls = {"n": 0}

        def fake_run_command(args, timeout_seconds=10):
            calls["n"] += 1
            if calls["n"] == 1:
                return 1, "", "json unavailable"
            return 1, "", text

        try:
            with (
                patch.object(app, "netbird_binary_path", return_value="/usr/local/bin/netbird"),
                patch.object(app, "run_command", side_effect=fake_run_command),
            ):
                return app.collect_netbird_status()
        finally:
            app._netbird_status_cache["value"] = None
            app._netbird_status_cache["at"] = 0.0

    def test_error_text_is_not_parsed_as_peer_ip(self) -> None:
        value = self._collect_with_text_output("TimeoutExpired: Command '['netbird', 'status']' timed out")
        self.assertIsNone(value["peer_ip"])

    def test_real_ip_is_still_extracted(self) -> None:
        value = self._collect_with_text_output("Connected, NetBird IP: 100.87.34.152/16 management: Connected")
        self.assertEqual(value["peer_ip"], "100.87.34.152")


class PairingStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.data = pathlib.Path(self.tmp.name)
        self.patches = [
            patch.object(app, "DATA_DIR", self.data),
            patch.object(app, "STATE_PATH", self.data / "state.json"),
            patch.object(app, "OPTIONS_PATH", self.data / "options.json"),
            patch.object(app, "HA_PROXY_CACHE_PATH", self.data / "ha_proxy_cache.json"),
            patch.object(app, "LOCAL_DEVICE_ID_PATH", self.data / "local_device_id"),
            patch.object(app, "NETBIRD_AGENT_PID_PATH", self.data / "netbird-agent.pid"),
            patch.object(app, "NETBIRD_AGENT_START_LOCK_PATH", self.data / "netbird-agent-start.lock"),
            patch.object(app, "NETBIRD_UP_LOCK_PATH", self.data / "netbird-up.lock"),
            patch.object(app, "NETBIRD_DIR", self.data / "netbird"),
            patch.object(app, "NETBIRD_CONFIG_PATH", self.data / "netbird" / "config.json"),
            patch.object(app, "NETBIRD_SOCKET_PATH", self.data / "netbird" / "netbird.sock"),
            patch.object(app, "NETBIRD_DAEMON_PID_PATH", self.data / "netbird" / "daemon.pid"),
            patch.object(app, "_options", {"hometunnel_url": "https://portal.example", "always_on": True, "access_mode": "route"}),
        ]
        for item in self.patches:
            item.start()
        app.ensure_data_dir()
        app._heartbeat_cache = {"fingerprint": None, "sent_at": 0.0}
        app._state = app.status_view_from_state(app.default_state(), app._options)
        app.write_json_file(app.STATE_PATH, app._state)

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def write_state(self, state: dict) -> dict:
        view = app.status_view_from_state({**app.default_state(), **state}, app._options)
        app._state = view
        app.write_json_file(app.STATE_PATH, view)
        return view

    def enrolled_state(self) -> dict:
        return self.write_state(
            {
                "paired": True,
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "setup_key": "setup-key",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
                "peer_name": "peer",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "signed_binding_token": "signed-binding-token",
                    "expected_netbird_label": "ht-device-device-1",
                    "status": "bound",
                    "valid": True,
                },
            }
        )

    def test_alive_agent_pid_without_daemon_pid_is_running_starting(self) -> None:
        app.write_agent_pid(1234)
        with patch.object(app, "pid_is_running", return_value=True):
            self.assertTrue(app.is_netbird_agent_running())

    def test_stale_dead_agent_pid_is_cleaned_and_not_running(self) -> None:
        app.write_agent_pid(1234)
        with patch.object(app, "pid_is_running", return_value=False):
            self.assertFalse(app.is_netbird_agent_running())
        self.assertFalse(app.NETBIRD_AGENT_PID_PATH.exists())

    def test_start_netbird_agent_skips_when_agent_pid_alive_without_daemon_pid(self) -> None:
        self.enrolled_state()
        app.write_agent_pid(1234)
        with patch.object(app, "pid_is_running", return_value=True), patch.object(
            app, "netbird_binary_path", return_value="/usr/bin/netbird"
        ), patch.object(app.subprocess, "Popen") as popen:
            started = app.start_netbird_agent_if_needed()
        self.assertFalse(started)
        popen.assert_not_called()

    def test_concurrent_start_netbird_agent_spawns_once(self) -> None:
        self.enrolled_state()
        spawned: list[int] = []
        spawn_lock = threading.Lock()

        class _Proc:
            def __init__(self, pid: int) -> None:
                self.pid = pid

        def fake_popen(*_args, **_kwargs):
            with spawn_lock:
                pid = 2000 + len(spawned)
                spawned.append(pid)
            time.sleep(0.05)
            return _Proc(pid)

        def fake_pid_is_running(pid: int) -> bool:
            with spawn_lock:
                return pid in spawned

        results: list[bool] = []

        def run_start() -> None:
            results.append(app.start_netbird_agent_if_needed())

        with patch.object(app, "netbird_binary_path", return_value="/usr/bin/netbird"), patch.object(
            app, "pid_is_running", side_effect=fake_pid_is_running
        ), patch.object(app.subprocess, "Popen", side_effect=fake_popen):
            threads = [threading.Thread(target=run_start) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(spawned, [2000])
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 1)

    def test_netbird_up_lock_prevents_overlapping_up_and_rechecks_status(self) -> None:
        state = self.enrolled_state()
        statuses = [
            {"connected": False, "peer_id": None, "peer_ip": None, "peer_name": None},
            {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"},
        ]
        up_calls = 0
        status_lock = threading.Lock()

        def fake_status() -> dict:
            with status_lock:
                return dict(statuses.pop(0) if statuses else statuses[-1])

        def fake_up(_state: dict, _options: dict) -> tuple[bool, str]:
            nonlocal up_calls
            up_calls += 1
            time.sleep(0.05)
            return True, "ok"

        results: list[tuple[bool, str, dict, bool]] = []

        def run_ready() -> None:
            results.append(app.ensure_netbird_ready_or_connected(state, app._options))

        with patch.object(app, "ensure_netbird_daemon", return_value=(True, "ok")), patch.object(
            app, "collect_netbird_status", side_effect=fake_status
        ), patch.object(app, "netbird_up", side_effect=fake_up):
            threads = [threading.Thread(target=run_ready) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(up_calls, 1)
        self.assertEqual([result[3] for result in results].count(True), 1)
        self.assertEqual([result[3] for result in results].count(False), 1)

    def test_netbird_up_skipped_when_status_connected_under_lock(self) -> None:
        state = self.enrolled_state()
        with patch.object(app, "ensure_netbird_daemon", return_value=(True, "ok")), patch.object(
            app, "collect_netbird_status", return_value={"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        ), patch.object(app, "netbird_up") as netbird_up:
            ok, message, status, attempted = app.ensure_netbird_ready_or_connected(state, app._options)
        self.assertTrue(ok)
        self.assertEqual(message, "already_connected")
        self.assertTrue(status["connected"])
        self.assertFalse(attempted)
        netbird_up.assert_not_called()

    def test_manual_restart_stops_before_single_locked_start(self) -> None:
        self.enrolled_state()
        spawned: list[int] = []

        class _Proc:
            pid = 3000

        def fake_popen(*_args, **_kwargs):
            spawned.append(_Proc.pid)
            return _Proc()

        with patch.object(app, "netbird_binary_path", return_value="/usr/bin/netbird"), patch.object(
            app, "stop_agent_supervisor", side_effect=app.clear_agent_pid
        ) as stop_agent, patch.object(app, "stop_netbird_daemon") as stop_daemon, patch.object(
            app, "pid_is_running", side_effect=lambda pid: pid in spawned
        ), patch.object(app.subprocess, "Popen", side_effect=fake_popen):
            response = app.api_agent_restart()
        self.assertEqual(response_status(response), 200)
        self.assertEqual(spawned, [3000])
        stop_agent.assert_called_once()
        stop_daemon.assert_called_once()

    def test_pairing_completion_does_not_spawn_second_agent_when_starting(self) -> None:
        self.write_state(
            {
                "pairing_session": {
                    "device_code": "device-code",
                    "user_code": "USER",
                    "verification_url": "https://portal.example/verify",
                    "pairing_started_at": app.now_iso(),
                    "pairing_expires_at": app.pairing_deadline_iso(app.now_iso()),
                    "pairing_status": "pending",
                    "pairing_inflight": False,
                    "poll_interval": 5,
                }
            }
        )
        app.write_agent_pid(1234)
        enroll_result = {
            "status": "approved",
            "device_id": "device-1",
            "home_id": "home-1",
            "device_token": "device-token",
            "netbird_peer_id": "nb-management-peer-1",
            "labels": ["ht-device-device-1"],
            "netbird": {
                "management_url": "https://mgmt.example",
                "setup_key": "setup-key",
                "peer_name": "peer",
            },
            "binding": {"binding_id": "binding-1", "signed_binding_token": "signed-binding-token", "expected_netbird_label": "ht-device-device-1"},
        }
        with patch.object(
            app,
            "portal_request_json",
            side_effect=[
                ({"status": "approved"}, "https://portal.example/status", "https://portal.example"),
                (enroll_result, "https://portal.example/enroll", "https://portal.example"),
            ],
        ), patch.object(app, "netbird_binary_path", return_value="/usr/bin/netbird"), patch.object(
            app, "pid_is_running", return_value=True
        ), patch.object(app.subprocess, "Popen") as popen:
            response = asyncio.run(app.api_auth_poll(_Request({"device_code": "device-code"})))
        self.assertEqual(response_status(response), 200)
        self.assertTrue(response_payload(response)["paired"])
        self.assertEqual(app._state["netbird_peer_id"], "nb-management-peer-1")
        popen.assert_not_called()

    def test_enrollment_persists_device_binding_id_as_binding_id(self) -> None:
        started = app.now_iso()
        self.write_state(
            {
                "pairing_session": {
                    "device_code": "device-code",
                    "user_code": "USER",
                    "verification_url": "https://portal.example/verify",
                    "pairing_started_at": started,
                    "pairing_expires_at": app.pairing_deadline_iso(started),
                    "pairing_status": "pending",
                    "pairing_inflight": False,
                }
            }
        )
        enroll_result = {
            "status": "approved",
            "device_id": "device-1",
            "home_id": "home-1",
            "device_token": "device-token",
            "labels": ["ht-device-device-1"],
            "netbird": {
                "management_url": "https://mgmt.example",
                "setup_key": "setup-key",
                "peer_name": "peer",
            },
            "device_binding": {
                "device_binding_id": "device-binding-1",
                "signed_binding_token": "signed-binding-token",
                "expected_netbird_label": "ht-device-device-1",
            },
        }

        with patch.object(
            app,
            "portal_request_json",
            side_effect=[
                ({"status": "approved"}, "https://portal.example/status", "https://portal.example"),
                (enroll_result, "https://portal.example/enroll", "https://portal.example"),
            ],
        ), patch.object(app, "netbird_binary_path", return_value=None):
            response = asyncio.run(app.api_auth_poll(_Request({"device_code": "device-code"})))

        self.assertEqual(response_status(response), 200)
        self.assertEqual(app._state["binding"]["binding_id"], "device-binding-1")
        self.assertEqual(app._state["binding"]["device_binding_id"], "device-binding-1")

    def test_heartbeat_sends_binding_id_with_bearer_token(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
                "setup_key": "setup-key",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "signed_binding_token": "signed-binding-token",
                    "expected_netbird_label": "ht-device-device-1",
                },
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
            }
        )
        status = {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        with patch.object(
            app,
            "portal_request_json",
            return_value=({"ok": True}, "https://portal.example/api/devices/device-1/heartbeat", "https://portal.example"),
        ) as portal_request:
            result = app.send_heartbeat(status, state, app._options)

        self.assertIsNone(result)
        kwargs = portal_request.call_args.kwargs
        self.assertEqual(kwargs["headers"], {"Authorization": "Bearer device-token"})
        self.assertEqual(kwargs["payload"]["bindingId"], "binding-1")
        self.assertEqual(kwargs["payload"]["bindingToken"], "signed-binding-token")
        self.assertEqual(kwargs["payload"]["peer"]["id"], "nb-management-peer-1")

    def test_heartbeat_sends_binding_id_without_binding_token_when_absent(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
                "setup_key": "setup-key",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "expected_netbird_label": "ht-device-device-1",
                },
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
            }
        )
        status = {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        with patch.object(
            app,
            "portal_request_json",
            return_value=({"ok": True}, "https://portal.example/api/devices/device-1/heartbeat", "https://portal.example"),
        ) as portal_request:
            result = app.send_heartbeat(status, state, app._options)

        self.assertIsNone(result)
        kwargs = portal_request.call_args.kwargs
        self.assertEqual(kwargs["payload"]["bindingId"], "binding-1")
        self.assertNotIn("bindingToken", kwargs["payload"])

    def test_missing_netbird_peer_id_fetches_config_before_heartbeat(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "setup_key": "setup-key",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "expected_netbird_label": "ht-device-device-1",
                },
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
            }
        )
        status = {
            "connected": True,
            "peer_id": "u" * 44,
            "wireguard_public_key": "u" * 44,
            "peer_ip": "100.64.0.1",
            "peer_name": "peer",
        }
        with patch.object(
            app,
            "portal_request_json",
            side_effect=[
                (
                    {
                        "ok": True,
                        "deviceId": "device-1",
                        "homeId": "home-1",
                        "netbird_peer_id": "nb-management-peer-1",
                        "binding": {
                            "device_binding_id": "binding-1",
                            "expected_netbird_label": "ht-device-device-1",
                        },
                    },
                    "https://portal.example/api/devices/device-1/config",
                    "https://portal.example",
                ),
                ({"ok": True}, "https://portal.example/api/devices/device-1/heartbeat", "https://portal.example"),
            ],
        ) as portal_request:
            result = app.send_heartbeat(status, state, app._options)

        self.assertIsNone(result)
        self.assertEqual(portal_request.call_args_list[0].args[:2], ("GET", "/api/devices/device-1/config"))
        heartbeat_kwargs = portal_request.call_args_list[1].kwargs
        self.assertEqual(heartbeat_kwargs["payload"]["peer"]["id"], "nb-management-peer-1")
        self.assertEqual(heartbeat_kwargs["payload"]["peer"]["wireguard_public_key"], "u" * 44)
        self.assertEqual(app._state["netbird_peer_id"], "nb-management-peer-1")

    def test_missing_netbird_peer_id_with_null_config_skips_heartbeat(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "setup_key": "setup-key",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "expected_netbird_label": "ht-device-device-1",
                },
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
            }
        )
        status = {"connected": True, "peer_id": "u" * 44, "wireguard_public_key": "u" * 44, "peer_ip": "100.64.0.1", "peer_name": "peer"}
        with patch.object(
            app,
            "portal_request_json",
            return_value=(
                {"ok": True, "deviceId": "device-1", "homeId": "home-1", "netbird_peer_id": None},
                "https://portal.example/api/devices/device-1/config",
                "https://portal.example",
            ),
        ) as portal_request:
            result = app.send_heartbeat(status, state, app._options)

        self.assertEqual(result, "netbird_management_peer_id_missing")
        portal_request.assert_called_once()
        self.assertEqual(app._state["heartbeat_error"], "netbird_management_peer_id_missing")
        self.assertIsNone(app._state["netbird_peer_id"])

    def test_load_state_preserves_netbird_peer_id(self) -> None:
        self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
            }
        )

        app.load_state()

        self.assertEqual(app._state["netbird_peer_id"], "nb-management-peer-1")

    def test_heartbeat_missing_binding_id_stays_local_and_preserves_credentials(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
                "setup_key": "setup-key",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "signed_binding_token": "signed-binding-token",
                    "expected_netbird_label": "ht-device-device-1",
                },
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
            }
        )
        status = {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        with patch.object(app, "portal_request_json") as portal_request, patch.object(app, "netbird_up") as netbird_up:
            result = app.send_heartbeat(status, state, app._options)

        self.assertEqual(result, "missing_binding_id")
        portal_request.assert_not_called()
        netbird_up.assert_not_called()
        self.assertEqual(app._state["heartbeat_error"], "missing_binding_id")
        self.assertEqual(app._state["last_error"], "missing_binding_id")
        self.assertEqual(app._state["device_token"], "device-token")
        self.assertEqual(app._state["setup_key"], "setup-key")

    def test_connected_heartbeat_binding_failure_degrades_without_clearing_credentials(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
                "setup_key": "setup-key",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "device_binding_id": "binding-1",
                    "signed_binding_token": "signed-binding-token",
                    "expected_netbird_label": "ht-device-device-1",
                    "status": "bound",
                    "valid": True,
                },
                "netbird": {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"},
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
            }
        )
        status = {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        failure = urllib.error.HTTPError(
            "https://portal.example/api/devices/device-1/heartbeat",
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"code":"binding_missing","message":"binding assertion missing"}'),
        )
        with patch.object(app, "portal_request_json", side_effect=failure), patch.object(app, "netbird_up") as netbird_up:
            result = app.send_heartbeat(status, state, app._options)

        self.assertEqual(result, "binding_missing")
        netbird_up.assert_not_called()
        self.assertEqual(app._state["recovery_state"], "re_pair_required")
        self.assertEqual(app._state["heartbeat_error"], "binding_missing")
        self.assertEqual(app._state["last_health_report_error"], "binding_missing")
        self.assertEqual(app._state["last_error"], "binding_missing")
        self.assertEqual(app._state["local_status"], "re_pair_required")
        self.assertEqual(app._state["pairing_state"], "error")
        self.assertEqual(app._state["device_token"], "device-token")
        self.assertIsNone(app._state["setup_key"])
        self.assertIsNone(app._state["binding"]["binding_id"])
        self.assertIsNone(app._state["binding"]["signed_binding_token"])
        self.assertNotEqual(app._state["binding"]["status"], "bound")
        self.assertEqual(app._state["netbird"]["peer_id"], "peer-1")

    def test_duplicate_pairing_blocked(self) -> None:
        _Thread.started = 0
        with patch.object(app.threading, "Thread", _Thread):
            first = app.api_auth_start()
            payload = response_payload(first)
            self.assertEqual(payload["status"], "starting")
            self.assertEqual(_Thread.started, 1)

            app.update_state(
                lambda state: app.update_pairing_session_state(
                    state,
                    {
                        "device_code": "device-code-1",
                        "user_code": "USER-1",
                        "verification_url": "https://portal.example/verify",
                        "pairing_started_at": app.now_iso(),
                        "pairing_expires_at": app.pairing_deadline_iso(app.now_iso()),
                        "pairing_status": "pending",
                        "pairing_inflight": False,
                    },
                    replace=True,
                )
            )
            second = app.api_auth_start()

        self.assertEqual(response_payload(second)["reused"], True)
        self.assertEqual(response_payload(second)["device_code"], "device-code-1")
        self.assertEqual(_Thread.started, 1)

    def test_expired_pairing_recovers_on_next_start(self) -> None:
        expired_start = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
        self.write_state(
            {
                "pairing_session": {
                    "device_code": "old-device-code",
                    "user_code": "OLD",
                    "verification_url": "https://portal.example/verify",
                    "pairing_started_at": expired_start,
                    "pairing_expires_at": expired_start,
                    "pairing_status": "pending",
                    "pairing_inflight": False,
                    "poll_interval": 5,
                }
            }
        )
        _Thread.started = 0
        with patch.object(app.threading, "Thread", _Thread):
            response = app.api_auth_start()

        payload = response_payload(response)
        self.assertEqual(payload["status"], "starting")
        self.assertIsNone(payload["device_code"])
        self.assertEqual(_Thread.started, 1)

    def test_pairing_state_persists_across_restart_states(self) -> None:
        cases = {
            "pending": {
                "pairing_session": {
                    "device_code": "device-code",
                    "user_code": "USER",
                    "verification_url": "https://portal.example/verify",
                    "pairing_started_at": app.now_iso(),
                    "pairing_expires_at": app.pairing_deadline_iso(app.now_iso()),
                    "pairing_status": "pending",
                    "pairing_inflight": False,
                    "poll_interval": 5,
                }
            },
            "approved": {"pairing_session": {"pairing_status": "approved"}},
            "connecting": {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "valid": True,
                    "status": "bound",
                },
            },
            "connected": {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "last_heartbeat_at": app.now_iso(),
                "netbird": {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer", "remote_peers": [], "raw": None},
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "valid": True,
                    "status": "bound",
                },
            },
            "error": {"recovery_state": "re_pair_required", "last_error": "re_pair_required"},
        }
        for expected, state in cases.items():
            with self.subTest(expected=expected):
                self.write_state({**state, "pairing_state": "stale_wrong_value"})
                app.load_state()
                self.assertEqual(app._state["pairing_state"], expected)

    def test_corrupted_state_file_is_backed_up(self) -> None:
        app.STATE_PATH.write_text('{"this is not json', encoding="utf-8")
        app.load_state()

        backups = list(self.data.glob("state.json.corrupted-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(app._state["pairing_state"], "error")
        self.assertEqual(app._state["recovery_state"], "corrupted_state_reset")
        self.assertEqual(app._state["last_error"], "state_file_corrupted")

    def test_portal_unreachable_is_reported_with_backoff(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token",
                "netbird_peer_id": "nb-management-peer-1",
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "valid": True,
                    "status": "bound",
                },
            }
        )
        status = {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        with patch.object(app, "request_json", side_effect=ConnectionRefusedError("portal down")):
            result = app.send_heartbeat(status, state, app._options)

        self.assertTrue(str(result).startswith("heartbeat_error:"))
        self.assertTrue(str(app._state["last_error"]).startswith("heartbeat_error:"))

    def test_portal_404_html_is_handled(self) -> None:
        classification = app.classify_heartbeat_failure(404, "<html>Not Found</html>")
        self.assertEqual(classification["error_code"], "heartbeat_http_404")
        self.assertEqual(classification["recovery_state"], "re_pair_required")
        self.assertEqual(app.safe_body_preview("<html>Not Found</html>"), "<html>Not Found</html>")

    def test_enroll_invalid_response(self) -> None:
        started = app.now_iso()
        self.write_state(
            {
                "pairing_session": {
                    "device_code": "device-code",
                    "user_code": "USER",
                    "verification_url": "https://portal.example/verify",
                    "pairing_started_at": started,
                    "pairing_expires_at": app.pairing_deadline_iso(started),
                    "pairing_status": "pending",
                    "pairing_inflight": False,
                }
            }
        )
        with patch.object(app, "portal_request_json", side_effect=[({"status": "approved"}, "https://portal.example/status", "https://portal.example"), ({}, "https://portal.example/enroll", "https://portal.example")]):
            response = asyncio.run(app.api_auth_poll(_Request({"device_code": "device-code"})))

        payload = response_payload(response)
        self.assertEqual(payload["code"], "enroll_invalid_response")
        self.assertFalse(app._state["paired"])

    def test_approved_pairing_retries_enroll_after_restart_with_persisted_attempt_flag(self) -> None:
        started = app.now_iso()
        self.write_state(
            {
                "device_auth": {
                    "device_code": "device-code",
                    "user_code": "USER",
                    "verification_url": "https://portal.example/verify",
                    "expires_at": app.pairing_deadline_iso(started),
                    "status": "approved",
                    "enroll_attempted": True,
                    "enroll_attempted_at": started,
                    "next_enroll_after": None,
                },
                "pairing_session": {
                    "device_code": "device-code",
                    "user_code": "USER",
                    "verification_url": "https://portal.example/verify",
                    "pairing_started_at": started,
                    "pairing_expires_at": app.pairing_deadline_iso(started),
                    "pairing_status": "approved",
                    "pairing_inflight": False,
                },
            }
        )
        app.load_state()
        self.assertFalse(app._state["device_auth"]["enroll_attempted"])
        enroll_result = {
            "status": "approved",
            "device_id": "device-1",
            "home_id": "home-1",
            "device_token": "device-token",
            "netbird": {
                "management_url": "https://mgmt.example",
                "setup_key": "setup-key",
                "peer_name": "peer",
            },
            "binding": {
                "binding_id": "binding-1",
                "signed_binding_token": "signed-binding-token",
                "expected_netbird_label": "ht-device-device-1",
            },
        }

        with patch.object(
            app,
            "portal_request_json",
            side_effect=[
                ({"status": "approved"}, "https://portal.example/status", "https://portal.example"),
                (enroll_result, "https://portal.example/enroll", "https://portal.example"),
            ],
        ) as portal_request, patch.object(app, "netbird_binary_path", return_value=None):
            response = asyncio.run(app.api_auth_poll(_Request({"device_code": "device-code"})))

        payload = response_payload(response)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["paired"])
        self.assertEqual(portal_request.call_count, 2)
        requested_paths = [call.args[1] for call in portal_request.call_args_list]
        self.assertIn("/api/agent/enroll", requested_paths)
        self.assertNotIn("/api/agent/device-auth/start", requested_paths)

    def test_netbird_join_failure_moves_to_error(self) -> None:
        state = self.write_state({"management_url": "https://mgmt.example", "setup_key": "setup-key-secret", "peer_name": "peer"})
        with patch.object(app, "netbird_binary_path", return_value="/usr/bin/netbird"), patch.object(
            app, "run_command", return_value=(1, "", "setup key revoked")
        ):
            ok, _message = app.netbird_up(state, app._options)

        self.assertFalse(ok)
        self.assertEqual(app._state["recovery_state"], "re_pair_required")
        self.assertIsNone(app._state["setup_key"])
        self.assertEqual(app._state["pairing_state"], "error")

    def test_netbird_join_failure_state_redacts_command_output(self) -> None:
        state = self.write_state({"management_url": "https://mgmt.example", "setup_key": "setup-key-secret", "peer_name": "peer"})
        with patch.object(app, "netbird_binary_path", return_value="/usr/bin/netbird"), patch.object(
            app, "run_command", return_value=(1, "", "join failed setup_key=setup-key-secret Authorization: Bearer bearer-secret")
        ):
            ok, message = app.netbird_up(state, app._options)

        persisted = json.loads(app.STATE_PATH.read_text(encoding="utf-8"))
        self.assertFalse(ok)
        for text in (message, app._state["last_error"], app._state["route"]["last_error"], persisted["last_error"], persisted["route"]["last_error"]):
            self.assertNotIn("setup-key-secret", text)
            self.assertNotIn("bearer-secret", text)
            self.assertIn("***redacted***", text)

    def test_status_state_fields_redact_error_secrets(self) -> None:
        self.write_state(
            {
                "device_token": "device-token-secret",
                "setup_key": "setup-key-secret",
                "binding": {"signed_binding_token": "signed-binding-secret"},
                "last_error": "failed token=device-token-secret signed_binding_token=signed-binding-secret",
                "heartbeat_error": "url=https://portal.example/cb?token=device-token-secret&code=abc123",
                "route": {"last_error": "setup_key=setup-key-secret"},
            }
        )

        payload = app.api_status()
        state = payload["state"]
        rendered = json.dumps(state)
        self.assertNotIn("device-token-secret", rendered)
        self.assertNotIn("setup-key-secret", rendered)
        self.assertNotIn("signed-binding-secret", rendered)
        self.assertIn("***redacted***", rendered)

    def test_api_error_response_redacts_exception_text(self) -> None:
        response = app.connectivity_error_response(
            "https://portal.example/api/agent/enroll?token=device-token-secret",
            RuntimeError("Authorization: Bearer bearer-secret device_token=device-token-secret"),
        )
        payload = response_payload(response)
        rendered = json.dumps(payload)
        self.assertNotIn("bearer-secret", rendered)
        self.assertNotIn("device-token-secret", rendered)
        self.assertIn("***redacted***", rendered)

    def test_persisted_state_redacts_error_fields(self) -> None:
        self.write_state({"device_token": "device-token-secret", "last_error": "device_token=device-token-secret"})
        persisted = app.STATE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("device_token=device-token-secret", persisted)
        self.assertIn("***redacted***", persisted)

    def test_heartbeat_failure_state_redacts_exception_text(self) -> None:
        state = self.write_state(
            {
                "device_id": "device-1",
                "home_id": "home-1",
                "management_url": "https://mgmt.example",
                "device_token": "device-token-secret",
                "netbird_peer_id": "nb-management-peer-1",
                "route": {"target_ip": "192.168.1.10", "ha_access_mode": "direct_ip", "needs_report": True},
                "binding": {
                    **app.default_binding_state(),
                    "device_id": "device-1",
                    "home_id": "home-1",
                    "binding_id": "binding-1",
                    "valid": True,
                    "status": "bound",
                },
            }
        )
        status = {"connected": True, "peer_id": "peer-1", "peer_ip": "100.64.0.1", "peer_name": "peer"}
        with patch.object(app, "request_json", side_effect=ConnectionRefusedError("device_token=device-token-secret")):
            result = app.send_heartbeat(status, state, app._options)

        persisted = app.STATE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("device_token=device-token-secret", str(result))
        self.assertNotIn("device_token=device-token-secret", app._state["last_error"])
        self.assertNotIn("device_token=device-token-secret", persisted)
        self.assertIn("***redacted***", str(result))

    def test_secret_redaction_filter_in_logs(self) -> None:
        secret = "secret-token-xyz"
        self.write_state(
            {
                "device_token": secret,
                "setup_key": "setup-key-secret",
                "binding": {
                    "binding_id": "binding-id-secret",
                    "device_binding_id": "device-binding-id-secret",
                    "signed_binding_token": "signed-binding-secret",
                },
            }
        )
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        app.LOG.addHandler(handler)
        try:
            app.LOG.warning(
                "token=%s Authorization: Bearer %s body=%s",
                secret,
                "bearer-token-abc",
                {
                    "setup_key": "setup-key-secret",
                    "binding_id": "binding-id-secret",
                    "device_binding_id": "device-binding-id-secret",
                    "signed_binding_token": "signed-binding-secret",
                },
            )
        finally:
            app.LOG.removeHandler(handler)

        output = stream.getvalue()
        self.assertNotIn(secret, output)
        self.assertNotIn("bearer-token-abc", output)
        self.assertNotIn("setup-key-secret", output)
        self.assertNotIn("binding-id-secret", output)
        self.assertNotIn("device-binding-id-secret", output)
        self.assertNotIn("signed-binding-secret", output)
        self.assertIn("***redacted***", output)

    def test_uvicorn_access_redaction_preserves_formatter_arguments(self) -> None:
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("172.30.32.2:12345", "GET", "/?token=secret-token-xyz", "1.1", 200),
            None,
        )

        # The record factory and the uvicorn logger can each apply the filter.
        app._redact_secrets_filter.filter(record)
        app._redact_secrets_filter.filter(record)

        self.assertEqual(len(record.args), 5)
        client_addr, method, path, http_version, status_code = record.args
        self.assertEqual(client_addr, "172.30.32.2:12345")
        self.assertEqual(method, "GET")
        self.assertEqual(http_version, "1.1")
        self.assertEqual(status_code, 200)
        self.assertIn("***redacted***", path)
        self.assertNotIn("secret-token-xyz", path)

    def test_qr_code_dependency_removed(self) -> None:
        dependency = "qr" + "code"
        helper_name = "make_" + "qr" + "_data_url"
        self.assertNotIn(dependency, app.__dict__)
        self.assertFalse(hasattr(app, helper_name))
        self.assertNotIn(dependency, REQUIREMENTS_PATH.read_text(encoding="utf-8"))
        self.assertNotIn("pillow", REQUIREMENTS_PATH.read_text(encoding="utf-8").lower())

    def test_no_direct_netbird_api_calls(self) -> None:
        source = APP_PATH.read_text(encoding="utf-8")
        self.assertIsNone(__import__("re").search(r"netbird\.io|/api/setup-keys|/api/peers/|/api/groups/|/api/policies/", source))


if __name__ == "__main__":
    unittest.main()

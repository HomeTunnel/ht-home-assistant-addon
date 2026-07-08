from __future__ import annotations

import pathlib
import io
import os
import sys
import types
import unittest
import urllib.error
from copy import deepcopy
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1] / "rootfs" / "opt" / "hometunnel"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEST_DATA_ROOT = pathlib.Path("/tmp/hometunnel-client-test-data")
TEST_DATA_ROOT.mkdir(parents=True, exist_ok=True)

_orig_mkdir = pathlib.Path.mkdir
_orig_write_text = pathlib.Path.write_text
_orig_read_text = pathlib.Path.read_text
_orig_open = pathlib.Path.open
_orig_exists = pathlib.Path.exists
_orig_unlink = pathlib.Path.unlink
_orig_replace = pathlib.Path.replace
_orig_os_replace = os.replace


def _redirect_path(path: pathlib.Path) -> pathlib.Path:
    try:
        if path.is_absolute() and str(path).startswith("/data"):
            return TEST_DATA_ROOT / str(path).lstrip("/")
    except Exception:
        pass
    return path


pathlib.Path.mkdir = lambda self, *args, **kwargs: _orig_mkdir(_redirect_path(self), *args, **kwargs)  # type: ignore[assignment]
pathlib.Path.write_text = lambda self, text, encoding=None: _orig_write_text(_redirect_path(self), text, encoding=encoding)  # type: ignore[assignment]
pathlib.Path.read_text = lambda self, *args, **kwargs: _orig_read_text(_redirect_path(self), *args, **kwargs)  # type: ignore[assignment]
pathlib.Path.open = lambda self, *args, **kwargs: _orig_open(_redirect_path(self), *args, **kwargs)  # type: ignore[assignment]
pathlib.Path.exists = lambda self: _orig_exists(_redirect_path(self))  # type: ignore[assignment]
pathlib.Path.unlink = lambda self, *args, **kwargs: _orig_unlink(_redirect_path(self), *args, **kwargs)  # type: ignore[assignment]
pathlib.Path.replace = lambda self, target: _orig_replace(_redirect_path(self), _redirect_path(pathlib.Path(target)))  # type: ignore[assignment]
os.replace = lambda src, dst: _orig_os_replace(_redirect_path(pathlib.Path(src)), _redirect_path(pathlib.Path(dst)))  # type: ignore[assignment]

if "httpx" not in sys.modules:
    httpx = types.ModuleType("httpx")

    class _Headers(dict):
        pass

    class _AsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

    class _Timeout:
        def __init__(self, *args, **kwargs) -> None:
            pass

    class _RequestError(Exception):
        pass

    class _ConnectError(_RequestError):
        pass

    class _ConnectTimeout(_RequestError):
        pass

    httpx.Headers = _Headers
    httpx.AsyncClient = _AsyncClient
    httpx.Timeout = _Timeout
    httpx.RequestError = _RequestError
    httpx.ConnectError = _ConnectError
    httpx.ConnectTimeout = _ConnectTimeout
    sys.modules["httpx"] = httpx

if "uvicorn" not in sys.modules:
    uvicorn = types.ModuleType("uvicorn")
    uvicorn.run = lambda *args, **kwargs: None
    sys.modules["uvicorn"] = uvicorn

if "websockets" not in sys.modules:
    websockets = types.ModuleType("websockets")

    class _WebSocketException(Exception):
        pass

    class _ConnectionClosed(Exception):
        pass

    async def _connect(*args, **kwargs):  # pragma: no cover - import stub
        raise RuntimeError("websockets stub")

    websockets.WebSocketException = _WebSocketException
    websockets.ConnectionClosed = _ConnectionClosed
    websockets.connect = _connect
    sys.modules["websockets"] = websockets

if "fastapi" not in sys.modules:
    fastapi = types.ModuleType("fastapi")

    class _DummyResponse:
        def __init__(self, *args, **kwargs) -> None:
            self.args = args
            self.kwargs = kwargs

    class _DummyWSDisconnect(Exception):
        pass

    class _DummyFastAPI:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn

            return wrapper

        get = post = websocket = on_event = api_route = middleware = _decorator

    fastapi.FastAPI = _DummyFastAPI
    fastapi.Request = object
    fastapi.WebSocket = object
    fastapi.WebSocketDisconnect = _DummyWSDisconnect
    fastapi_responses = types.ModuleType("fastapi.responses")
    fastapi_responses.HTMLResponse = _DummyResponse
    fastapi_responses.JSONResponse = _DummyResponse
    fastapi_responses.PlainTextResponse = _DummyResponse
    fastapi_responses.Response = _DummyResponse
    fastapi_responses.StreamingResponse = _DummyResponse
    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.responses"] = fastapi_responses

if "starlette.background" not in sys.modules:
    starlette = types.ModuleType("starlette")
    starlette_background = types.ModuleType("starlette.background")

    class _BackgroundTask:
        def __init__(self, *args, **kwargs) -> None:
            pass

    starlette_background.BackgroundTask = _BackgroundTask
    sys.modules["starlette"] = starlette
    sys.modules["starlette.background"] = starlette_background

from app import (  # type: ignore
    classify_heartbeat_failure,
    classify_setup_key_join_failure,
    default_binding_state,
    heartbeat_fingerprint,
    heartbeat_telemetry_gaps,
    status_view_from_state,
)
import app as hometunnel_app  # type: ignore

pathlib.Path.mkdir = _orig_mkdir  # type: ignore[assignment]
pathlib.Path.write_text = _orig_write_text  # type: ignore[assignment]
pathlib.Path.read_text = _orig_read_text  # type: ignore[assignment]
pathlib.Path.open = _orig_open  # type: ignore[assignment]
pathlib.Path.exists = _orig_exists  # type: ignore[assignment]
pathlib.Path.unlink = _orig_unlink  # type: ignore[assignment]
pathlib.Path.replace = _orig_replace  # type: ignore[assignment]
os.replace = _orig_os_replace  # type: ignore[assignment]


class ClientRecoveryStateTests(unittest.TestCase):
    def test_status_view_keeps_enrollment_without_setup_key(self) -> None:
        state = {
            "paired": False,
            "device_id": "device-123",
            "home_id": "home-456",
            "management_url": "https://management.example",
            "device_token": "device-token-abc",
            "setup_key": None,
            "binding": {
                **default_binding_state(),
                "device_id": "device-123",
                "home_id": "home-456",
                "binding_id": "binding-1",
                "device_binding_id": "device-binding-1",
                "signed_binding_token": "signed-token",
                "expected_netbird_label": "ht-device-device-123",
                "netbird_labels": ["ht-device-device-123"],
                "status": "bound",
                "valid": True,
                "missing_fields": [],
            },
        }

        view = status_view_from_state(state)

        self.assertTrue(view["paired"])
        self.assertEqual(view["local_status"], "enrolled")
        self.assertEqual(view["binding"]["status"], "bound")

    def test_paired_state_with_missing_binding_material_surfaces_local_warning(self) -> None:
        state = {
            "paired": True,
            "device_id": "device-123",
            "home_id": "home-456",
            "management_url": "https://management.example",
            "device_token": "device-token-abc",
            "binding": {
                **default_binding_state(),
                "device_id": "device-123",
                "home_id": "home-456",
                "status": "partial",
                "valid": False,
                "missing_fields": ["binding_id", "signed_binding_token"],
            },
        }

        view = status_view_from_state(state)

        self.assertEqual(view["local_status"], "binding_material_missing")
        self.assertIn("Binding material is incomplete", view["local_status_detail"])

    def test_heartbeat_binding_stale_maps_to_explicit_recovery(self) -> None:
        classification = classify_heartbeat_failure(
            401,
            '{"code":"binding_token_stale","message":"binding token is stale"}',
        )

        self.assertEqual(classification["recovery_state"], "stale_binding")
        self.assertEqual(classification["error_code"], "binding_token_stale")
        self.assertTrue(classification["clear_binding"])
        self.assertTrue(classification["clear_setup_key"])

    def test_heartbeat_binding_missing_maps_to_explicit_recovery(self) -> None:
        classification = classify_heartbeat_failure(
            401,
            '{"code":"binding_missing","message":"binding assertion missing"}',
        )

        self.assertEqual(classification["recovery_state"], "re_pair_required")
        self.assertEqual(classification["error_code"], "binding_missing")
        self.assertTrue(classification["clear_binding"])
        self.assertTrue(classification["clear_setup_key"])

    def test_missing_peer_id_surfaces_explicit_local_diagnostic(self) -> None:
        state = {
            "paired": True,
            "device_id": "device-123",
            "home_id": "home-456",
            "device_token": "device-token-abc",
            "management_url": "https://management.example",
            "binding": {
                **default_binding_state(),
                "device_id": "device-123",
                "home_id": "home-456",
                "binding_id": "binding-1",
                "device_binding_id": "binding-1",
                "signed_binding_token": "signed-token-secret",
                "status": "bound",
                "valid": True,
                "missing_fields": [],
                "persisted_at": "2026-04-06T12:00:00.000Z",
            },
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
                "resolved_target_hostname": "homeassistant.local",
                "current_endpoint": "http://192.168.68.141:8123",
                "target_port": 8123,
                "health_status": "healthy",
                "healthy": True,
                "local_tcp_8123_reachable": True,
                "target_reachable": True,
                "route_network": "192.168.68.141/32",
                "desired_advertise_routes": "192.168.68.141/32",
                "applied_advertise_routes": "192.168.68.141/32",
                "route_ids": ["route-1"],
                "peer_group_ids": ["group-1"],
                "policy_ids": ["policy-1"],
            },
            "agent_running": True,
        }
        state_snapshot = deepcopy(state)

        def fake_read_json_file(path, fallback):
            return deepcopy(state_snapshot)

        def fake_write_json_file(path, value):
            state_snapshot.clear()
            state_snapshot.update(deepcopy(value))

        with (
            patch.object(hometunnel_app, "portal_request_json") as portal_request_json,
            patch.object(hometunnel_app, "read_json_file", side_effect=fake_read_json_file),
            patch.object(hometunnel_app, "write_json_file", side_effect=fake_write_json_file),
        ):
            error = hometunnel_app.send_heartbeat(
                {"connected": True, "peer_ip": "100.64.0.10", "peer_name": "haos-peer"},
                state,
                {"health_check_interval_seconds": 600},
            )

        self.assertEqual(error, "netbird_management_peer_id_missing")
        portal_request_json.assert_called_once()
        self.assertEqual(state_snapshot["heartbeat_error"], "netbird_management_peer_id_missing")
        self.assertEqual(state_snapshot["last_health_report_error"], "netbird_management_peer_id_missing")
        self.assertEqual(state_snapshot["last_error"], "netbird_management_peer_id_missing")

    def test_revoked_device_credential_maps_to_explicit_recovery(self) -> None:
        classification = classify_heartbeat_failure(
            403,
            '{"code":"device_credential_revoked","message":"credential revoked"}',
        )

        self.assertEqual(classification["recovery_state"], "device_credential_revoked")
        self.assertEqual(classification["error_code"], "device_credential_revoked")
        self.assertTrue(classification["clear_device_token"])
        self.assertTrue(classification["clear_setup_key"])

    def test_heartbeat_409_peer_conflicts_are_distinct_non_retryable_failures(self) -> None:
        cases = [
            ('{"error":"peer_conflict","code":"peer_home_mismatch"}', "peer_home_mismatch", "peer_conflict"),
            ('{"code":"peer_identity_mismatch"}', "peer_identity_mismatch", "peer_mismatch"),
            ("portal rejected peer_home_mismatch for stale owner", "peer_home_mismatch", "peer_conflict"),
        ]
        for body, expected_error, expected_recovery in cases:
            with self.subTest(body=body):
                classification = classify_heartbeat_failure(409, body)

                self.assertEqual(classification["error_code"], expected_error)
                self.assertEqual(classification["recovery_state"], expected_recovery)
                self.assertNotEqual(classification["error_code"], "heartbeat_http_409")
                self.assertTrue(classification["clear_binding"])
                self.assertTrue(classification["destructive"])
                self.assertIn("Reset pairing", classification["message"])

    def test_unknown_409_preserves_credentials(self) -> None:
        classification = classify_heartbeat_failure(409, '{"code":"conflict","message":"try later"}')

        self.assertEqual(classification["recovery_state"], "heartbeat_failed_unknown")
        self.assertEqual(classification["error_code"], "heartbeat_http_409_unknown")
        self.assertFalse(classification["clear_binding"])
        self.assertFalse(classification["clear_device_token"])
        self.assertFalse(classification["destructive"])

    def test_heartbeat_403_binding_codes_are_deterministic(self) -> None:
        expected = {
            "binding_home_mismatch": ("re_pair_required", "binding_home_mismatch"),
            "binding_rotated": ("re_pair_required", "binding_rotated"),
            "binding_revoked": ("re_pair_required", "binding_revoked"),
            "missing_binding": ("re_pair_required", "missing_binding"),
            "invalid_binding": ("re_pair_required", "invalid_binding"),
            "binding_peer_mismatch": ("peer_mismatch", "binding_peer_mismatch"),
            "binding_device_disabled": ("re_pair_required", "binding_device_disabled"),
            "binding_device_not_haos": ("fatal_misconfiguration", "binding_device_not_haos"),
            "unauthorized": ("re_pair_required", "unauthorized"),
            "invalid_token": ("re_pair_required", "invalid_token"),
        }
        for code, (expected_recovery, expected_error) in expected.items():
            with self.subTest(code=code):
                classification = classify_heartbeat_failure(403, f'{{"code":"{code}","message":"portal rejected"}}')

                self.assertEqual(classification["recovery_state"], expected_recovery)
                self.assertEqual(classification["error_code"], expected_error)
                self.assertTrue(classification["destructive"])
                self.assertTrue(classification["clear_binding"])

    def test_unknown_403_preserves_credentials(self) -> None:
        classification = classify_heartbeat_failure(403, '{"code":"edge_forbidden","message":"temporary"}')

        self.assertEqual(classification["recovery_state"], "heartbeat_failed_unknown")
        self.assertEqual(classification["error_code"], "heartbeat_http_403_unknown")
        self.assertFalse(classification["clear_binding"])
        self.assertFalse(classification["clear_device_token"])
        self.assertFalse(classification["destructive"])

    def test_status_does_not_report_bound_after_known_portal_rejection(self) -> None:
        state = {
            "paired": True,
            "device_id": "device-123",
            "home_id": "home-456",
            "management_url": "https://management.example",
            "device_token": "device-token-abc",
            "recovery_state": "peer_conflict",
            "last_error": "peer_home_mismatch",
            "binding": {
                **default_binding_state(),
                "device_id": "device-123",
                "home_id": "home-456",
                "binding_id": None,
                "device_binding_id": None,
                "signed_binding_token": None,
                "portal_validation_error": "peer_home_mismatch",
                "portal_validation_reported_at": "2026-04-06T12:00:00.000Z",
            },
        }

        view = status_view_from_state(state)

        self.assertEqual(view["local_status"], "peer_conflict")
        self.assertEqual(view["pairing_state"], "error")
        self.assertNotEqual(view["binding"]["status"], "bound")
        self.assertEqual(view["binding"]["portal_validation_error"], "peer_home_mismatch")

    def test_clear_local_identity_state_resets_pairing_material(self) -> None:
        with patch.object(hometunnel_app, "ensure_local_device_id", return_value="local-test"):
            state = {
                **hometunnel_app.default_state(),
                "paired": True,
                "home_id": "home-a",
                "device_id": "device-a",
                "device_token": "token-a",
                "setup_key": "setup-a",
                "netbird_peer_id": "peer-a",
                "recovery_state": "re_pair_required",
                "heartbeat_error": "binding_home_mismatch",
                "last_health_report_error": "binding_home_mismatch",
                "pairing_session": {"device_code": "code-a", "pairing_status": "pending"},
                "binding": {
                    **default_binding_state(),
                    "device_id": "device-a",
                    "home_id": "home-a",
                    "binding_id": "binding-a",
                    "device_binding_id": "binding-a",
                    "signed_binding_token": "binding-token-a",
                },
            }

            cleared = hometunnel_app.clear_local_identity_state(state, reset_route=True)

        self.assertTrue(cleared["home_id"])
        self.assertIsNone(state["home_id"])
        self.assertIsNone(state["device_id"])
        self.assertIsNone(state["device_token"])
        self.assertIsNone(state["setup_key"])
        self.assertIsNone(state["netbird_peer_id"])
        self.assertIsNone(state["heartbeat_error"])
        self.assertIsNone(state["recovery_state"])
        self.assertEqual(state["binding"]["status"], "missing")
        self.assertEqual(state["pairing_session"], hometunnel_app.default_pairing_session_state())

    def test_portal_reset_cleanup_result_mapping(self) -> None:
        base_state = {
            "portal_base_url": "https://portal.example",
            "home_id": "home-a",
            "device_id": "device-a",
            "device_token": "token-a",
            "netbird_peer_id": "peer-a",
            "binding": {
                **default_binding_state(),
                "device_id": "device-a",
                "home_id": "home-a",
                "binding_id": "binding-a",
                "signed_binding_token": "binding-token-a",
            },
        }

        with patch.object(hometunnel_app, "portal_request_json", return_value=({"ok": True}, "https://portal.example/api/agent/binding/revoke", "https://portal.example")):
            self.assertEqual(hometunnel_app.portal_reset_cleanup_result(base_state)["result"], "success")

        with patch.object(hometunnel_app, "portal_request_json", return_value=([], "https://portal.example/api/agent/binding/revoke", "https://portal.example")):
            self.assertEqual(hometunnel_app.portal_reset_cleanup_result(base_state)["result"], "invalid_response")

        http_cases = {
            404: "already_revoked",
            410: "already_revoked",
            401: "unauthorized_stale_credentials",
            403: "unauthorized_stale_credentials",
            405: "unsupported",
            501: "unsupported",
            500: "server_error",
        }
        for status, expected in http_cases.items():
            with self.subTest(status=status):
                error = urllib.error.HTTPError(
                    "https://portal.example/api/agent/binding/revoke",
                    status,
                    "error",
                    {},
                    io.BytesIO(b'{"code":"error"}'),
                )
                with patch.object(hometunnel_app, "portal_request_json", side_effect=error):
                    self.assertEqual(hometunnel_app.portal_reset_cleanup_result(base_state)["result"], expected)

        with patch.object(hometunnel_app, "portal_request_json", side_effect=TimeoutError("timeout")):
            self.assertEqual(hometunnel_app.portal_reset_cleanup_result(base_state)["result"], "network_error")

    def test_repair_after_reset_does_not_reuse_old_identity(self) -> None:
        old_state = {
            "home_id": "home-a",
            "device_id": "device-a",
            "device_token": "token-a",
            "setup_key": "setup-a",
            "recovery_state": "re_pair_required",
            "binding": {
                **default_binding_state(),
                "device_id": "device-a",
                "home_id": "home-a",
                "binding_id": "binding-a",
                "signed_binding_token": "binding-token-a",
            },
        }
        with patch.object(hometunnel_app, "ensure_local_device_id", return_value="local-test"):
            hometunnel_app.clear_local_identity_state(old_state, reset_route=True)
        incoming = {
            "device_id": "device-b",
            "home_id": "home-b",
            "device_token": "token-b",
            "management_url": "https://management.example",
            "setup_key": "setup-b",
            "labels": ["ht-device-device-b"],
            "binding": {
                "device_id": "device-b",
                "home_id": "home-b",
                "binding_id": "binding-b",
                "device_binding_id": "binding-b",
                "signed_binding_token": "binding-token-b",
                "expected_netbird_label": "ht-device-device-b",
            },
        }

        merged = hometunnel_app.merge_enrollment_fields(old_state, incoming)
        normalized = hometunnel_app.normalize_binding_state(
            {**old_state, "device_id": merged["device_id"], "home_id": merged["home_id"], "labels": merged["labels"], "binding": merged["binding"]}
        )

        self.assertEqual(merged["home_id"], "home-b")
        self.assertEqual(merged["device_id"], "device-b")
        self.assertEqual(normalized["binding_id"], "binding-b")
        self.assertNotIn("home-a", str(merged))
        self.assertNotIn("binding-a", str(merged))
        self.assertIsNone(old_state["recovery_state"])

    def test_mixed_identity_detection_rejects_inconsistent_binding_payload(self) -> None:
        mixed = hometunnel_app.normalize_binding_state(
            {
                "device_id": "device-b",
                "home_id": "home-b",
                "labels": ["ht-device-device-b"],
                "binding": {
                    "device_id": "device-a",
                    "home_id": "home-a",
                    "binding_id": "binding-a",
                    "signed_binding_token": "binding-token-a",
                    "expected_netbird_label": "ht-device-device-b",
                },
            }
        )

        self.assertEqual(mixed["status"], "invalid")
        self.assertEqual(mixed["validation_error"], "binding_device_id_mismatch")

    def test_setup_key_join_failure_is_not_reused(self) -> None:
        self.assertEqual(classify_setup_key_join_failure("setup key revoked by portal"), "setup_key_rejected")

    def test_pending_target_and_route_ids_force_telemetry_refresh(self) -> None:
        route_state = {
            "access_mode": "route",
            "pending_target_ip": "192.168.68.141",
            "pending_target_hostname": "homeassistant.local",
            "route_ids": [],
            "peer_group_ids": [],
            "policy_ids": [],
        }

        gaps = heartbeat_telemetry_gaps(route_state)

        self.assertIn("target_observation:pending_target_change", gaps)
        self.assertIn("route_ids_missing", gaps)
        self.assertIn("peer_group_ids_missing", gaps)
        self.assertIn("policy_ids_missing", gaps)

    def test_unresolved_target_state_forces_telemetry_refresh(self) -> None:
        route_state = {
            "access_mode": "route",
            "route_ids": ["route-1"],
            "peer_group_ids": ["group-1"],
            "policy_ids": ["policy-1"],
        }

        gaps = heartbeat_telemetry_gaps(route_state)

        self.assertIn("target_observation:unresolved", gaps)

    def test_stable_route_with_ids_does_not_force_telemetry_refresh(self) -> None:
        route_state = {
            "access_mode": "route",
            "target_ip": "192.168.68.141",
            "target_hostname": "homeassistant.local",
            "route_ids": ["route-1"],
            "peer_group_ids": ["group-1"],
            "policy_ids": ["policy-1"],
        }

        self.assertEqual(heartbeat_telemetry_gaps(route_state), [])

    def test_heartbeat_cache_fingerprint_changes_when_binding_rotates(self) -> None:
        status = {"connected": True, "peer_id": "peer-123", "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        base_state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
                "resolved_target_hostname": "homeassistant.local",
                "current_endpoint": "http://192.168.68.141:8123",
            },
            "binding": {
                **default_binding_state(),
                "binding_id": "binding-1",
                "device_binding_id": "binding-1",
                "signed_binding_token": "signed-token-1",
                "rotation_count": 1,
                "status": "bound",
                "valid": True,
            },
        }

        fingerprint_one = heartbeat_fingerprint(hometunnel_app.build_heartbeat_payload(status, base_state), base_state)
        rotated_state = deepcopy(base_state)
        rotated_state["binding"]["binding_id"] = "binding-2"
        rotated_state["binding"]["device_binding_id"] = "binding-2"
        rotated_state["binding"]["signed_binding_token"] = "signed-token-2"
        rotated_state["binding"]["rotation_count"] = 2

        fingerprint_two = heartbeat_fingerprint(hometunnel_app.build_heartbeat_payload(status, rotated_state), rotated_state)

        self.assertNotEqual(fingerprint_one, fingerprint_two)

    def test_heartbeat_send_logs_do_not_include_raw_binding_token(self) -> None:
        status = {"connected": True, "peer_id": "peer-123", "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        state = {
            "paired": True,
            "device_id": "device-123",
            "home_id": "home-456",
            "device_token": "device-token-abc",
            "netbird_peer_id": "nb-management-peer-123",
            "management_url": "https://management.example",
            "binding": {
                **default_binding_state(),
                "device_id": "device-123",
                "home_id": "home-456",
                "binding_id": "binding-1",
                "device_binding_id": "binding-1",
                "signed_binding_token": "signed-token-secret",
                "status": "bound",
                "valid": True,
                "missing_fields": [],
                "persisted_at": "2026-04-06T12:00:00.000Z",
            },
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
                "resolved_target_hostname": "homeassistant.local",
                "current_endpoint": "http://192.168.68.141:8123",
                "target_port": 8123,
                "health_status": "healthy",
                "healthy": True,
                "local_tcp_8123_reachable": True,
                "target_reachable": True,
                "route_network": "192.168.68.141/32",
                "desired_advertise_routes": "192.168.68.141/32",
                "applied_advertise_routes": "192.168.68.141/32",
                "route_ids": ["route-1"],
                "peer_group_ids": ["group-1"],
                "policy_ids": ["policy-1"],
            },
            "agent_running": True,
        }

        captured: list[str] = []

        class _LogCapture:
            def _record(self, level: str, message: str, *args: object) -> None:
                rendered = message % args if args else message
                captured.append(f"{level}:{rendered}")

            def debug(self, message: str, *args: object) -> None:
                self._record("debug", message, *args)

            def info(self, message: str, *args: object) -> None:
                self._record("info", message, *args)

            def warning(self, message: str, *args: object) -> None:
                self._record("warning", message, *args)

            def error(self, message: str, *args: object) -> None:
                self._record("error", message, *args)

        fake_response = {
            "ok": True,
            "device_binding": {"status": "binding_validated", "diagnostics": ["binding_validated"]},
            "route": {"route_ids": ["route-1"], "policy_ids": ["policy-1"], "peer_group_ids": ["group-1"]},
        }
        state_snapshot = deepcopy(state)

        def fake_read_json_file(path, fallback):
            return deepcopy(state_snapshot)

        def fake_write_json_file(path, value):
            state_snapshot.clear()
            state_snapshot.update(deepcopy(value))

        with (
            patch.object(hometunnel_app, "LOG", _LogCapture()),
            patch.object(hometunnel_app, "default_state", return_value=deepcopy(state_snapshot)),
            patch.object(hometunnel_app, "portal_request_json", return_value=(fake_response, "https://portal.example/api/devices/device-123/heartbeat", "https://portal.example")),
            patch.object(hometunnel_app, "build_health_report", return_value={
                "last_health_check_at": "2026-04-06T12:00:00.000Z",
                "last_agent_report_at": "2026-04-06T12:00:00.000Z",
                "last_health_result": "ok",
            }),
            patch.object(hometunnel_app, "heartbeat_telemetry_gaps", return_value=[]),
            patch.object(hometunnel_app, "extract_route_status_from_response", return_value={
                "route_ids": ["route-1"],
                "peer_group_ids": ["group-1"],
                "policy_ids": ["policy-1"],
                "applied_advertise_routes": "192.168.68.141/32",
                "healthy": True,
                "last_error": None,
            }),
            patch.object(hometunnel_app, "read_json_file", side_effect=fake_read_json_file),
            patch.object(hometunnel_app, "write_json_file", side_effect=fake_write_json_file),
        ):
            error = hometunnel_app.send_heartbeat(status, state, {"health_check_interval_seconds": 600})

        self.assertIsNone(error)
        self.assertTrue(captured)
        combined_logs = "\n".join(captured)
        self.assertIn("binding_token_present=True", combined_logs)
        self.assertNotIn("binding-1", combined_logs)
        self.assertNotIn("signed-token-secret", combined_logs)


if __name__ == "__main__":
    unittest.main()

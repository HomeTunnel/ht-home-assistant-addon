"""Run separately from stub-based unit tests with installed runtime dependencies."""
import asyncio
import io
import json
import logging
import pathlib
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import httpx
import uvicorn
import websockets
import fastapi
import starlette.background
# Reuse only the import-time /data redirection. Real packages above prevent stubs.
import test_client_recovery_state
import app
from safe_logging import EventFormatter
from homeview import HomeviewRuntime
from homeview_checks import RequestFailure, request_json



class RuntimeSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_startup_unavailable_then_periodic_recovery(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(app, "update_proxy_runtime_state"), \
             patch.object(app, "ensure_data_dir"):
            resolver = app.HomeAssistantUpstreamResolver(pathlib.Path(directory) / "cache.json")
            with patch.object(app, "_proxy_resolver", resolver), \
                 patch.object(resolver, "_candidate_urls", return_value=[
                     ("supervisor_core_info", "http://172.30.32.1:80")]), \
                 patch.object(resolver, "_health_check", return_value=(False, "unavailable")) as probe:
                with patch.object(app.threading, "Thread") as thread:
                    await app.proxy_startup_event()
                    thread.return_value.start.assert_called_once()
                try:
                    self.assertIsNone(resolver.snapshot()["selected_url"])
                    transport = httpx.ASGITransport(app=app.proxy_app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://addon") as client:
                        self.assertEqual((await client.get("/manifest.json")).status_code, 503)
                        self.assertEqual((await client.get("/health")).status_code, 200)
                    probe.return_value = (True, "ready")
                    with patch.object(app._proxy_stop_event, "wait", side_effect=[False, True]) as wait:
                        app.start_proxy_resolver_loop()
                    wait.assert_called_with(app.PROXY_RESOLVE_INTERVAL_SECONDS)
                    self.assertEqual(resolver.resolve(), "http://172.30.32.1:80")
                finally:
                    await app.proxy_shutdown_event()

    async def test_overlay_cannot_spoof_ingress_with_forwarded_headers(self):
        transport = httpx.ASGITransport(app=app.app, client=("192.0.2.47", 4567))
        async with httpx.AsyncClient(transport=transport, base_url="http://addon") as client:
            for path in ("/api/status", "/api/pairing/reset", "/api/auth/start"):
                response = await client.post(path, headers={"X-Forwarded-For": "172.30.32.2"})
                self.assertEqual(response.status_code, 403)
            self.assertEqual((await client.get("/health")).status_code, 200)

    async def test_homeview_ingress_is_private_and_requires_csrf_header(self):
        with tempfile.TemporaryDirectory() as directory:
            state = {
                "portal_base_url": "https://portal.example", "home_id": "a-home",
                "device_id": "a-device", "device_token": "test-credential",
                "binding": {"binding_id": "a-binding"}, "netbird": {"connected": False},
            }
            runtime = HomeviewRuntime(pathlib.Path(directory) / "homeview.json", lambda: state)
            with patch.object(app, "homeview", runtime):
                local = httpx.ASGITransport(app=app.app, client=("172.30.32.2", 4567))
                overlay = httpx.ASGITransport(app=app.app, client=("192.0.2.47", 4567))
                headers = {"X-Homeview-UI": "1"}
                path = "/api/homeview/local"
                async with httpx.AsyncClient(transport=overlay, base_url="http://addon") as client:
                    self.assertEqual((await client.get(path, headers=headers)).status_code, 403)
                    self.assertEqual((await client.post(path, json={"enabled": False}, headers=headers)).status_code, 403)
                async with httpx.AsyncClient(transport=local, base_url="http://addon") as client:
                    self.assertIn("Review sharing", (await client.get("/")).text)
                    self.assertEqual((await client.get("/homeview.js")).status_code, 200)
                    self.assertEqual((await client.get(path)).status_code, 403)
                    self.assertEqual((await client.post(path, json={"enabled": False},
                        headers={**headers, "Sec-Fetch-Site": "cross-site"})).status_code, 403)
                    self.assertEqual((await client.post(path, content=b"{}", headers=headers)).status_code, 415)
                    response = await client.get(path, headers=headers)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.headers["cache-control"], "private, no-store")
                    self.assertFalse(response.json()["enabled"])
                    enabled = {
                        "enabled": True, "revision": None,
                        "monitors": [{"kind": "ha_api", "label": "Home Assistant"},
                                     {"kind": "battery_binary", "label": "Sensor battery", "entity": "binary_sensor.test_battery"}],
                    }
                    saved = await client.post(path, json=enabled, headers=headers)
                    self.assertEqual(saved.status_code, 200, saved.text)
                    self.assertTrue(saved.json()["enabled"])
                    self.assertNotIn("test-credential", saved.text)
                    self.assertEqual((await client.post(path, json=enabled, headers=headers)).status_code, 409)
                    off = await client.post(path, json={"enabled": False}, headers=headers)
                    self.assertFalse(off.json()["enabled"])

    async def test_homeview_worker_reports_while_netbird_is_down(self):
        fixture_dir = pathlib.Path(__file__).with_name("fixtures") / "homeview_v1"
        config = json.loads((fixture_dir / "config.json").read_text())
        ack = threading.Event()
        requests = []

        async def homeview_transport(request):
            path = request.url.path
            requests.append((path, request.headers.get("authorization")))
            if path.endswith("/config"):
                payload = {**config, "session": None, "manifestRevision": 0}
            elif path.endswith("/monitors"):
                body = json.loads(request.content)
                payload = {**config, "session": {**config["session"], "bootId": body["bootId"]}}
            elif path == "/core/api/":
                payload = {"message": "API running."}
            elif path.endswith("/reports"):
                body = json.loads(request.content)
                self.assertEqual(body["observations"][0]["result"], "responding")
                self.assertEqual(body["sequence"], 1)
                payload = json.loads((fixture_dir / "reportResponse.json").read_text())
                ack.set()
            else:
                raise AssertionError("Unexpected Homeview request")
            return httpx.Response(200, stream=httpx.ByteStream(json.dumps(payload).encode()))

        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"SUPERVISOR_TOKEN": "supervisor-secret"}):
            state = {
                "portal_base_url": "https://portal.example", "home_id": "a-home",
                "device_id": "a-device", "device_token": "device-secret",
                "binding": {"binding_id": "a-binding"}, "netbird": {"connected": False},
            }
            runtime = HomeviewRuntime(pathlib.Path(directory) / "homeview.json", lambda: state)
            runtime.apply({"enabled": True, "revision": None, "monitors": [{"kind": "ha_api", "label": "Home Assistant"}]})
            transport = httpx.MockTransport(homeview_transport)
            create = httpx.AsyncClient
            with patch("homeview.httpx.AsyncClient", side_effect=lambda **kw: create(transport=transport, **kw)):
                try:
                    runtime.start()
                    self.assertTrue(await asyncio.to_thread(ack.wait, 2), requests)
                finally:
                    runtime.stop()
                    await asyncio.to_thread(runtime.thread.join, 2)
                self.assertFalse(runtime.thread.is_alive())
            self.assertEqual(requests, [
                ("/api/devices/a-device/homeview/config", "Bearer device-secret"),
                ("/api/devices/a-device/homeview/monitors", "Bearer device-secret"),
                ("/core/api/", "Bearer supervisor-secret"),
                ("/api/devices/a-device/homeview/reports", "Bearer device-secret"),
            ])

    async def test_homeview_transport_ignores_redirects_and_never_exposes_error_text(self):
        calls = []

        async def redirect(request):
            calls.append(str(request.url))
            return httpx.Response(307, headers={"Location": "https://other.example/leaked"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(redirect), follow_redirects=True) as client:
            with self.assertRaises(RequestFailure) as failure:
                await request_json(client, "GET", "https://portal.example/config", {"Authorization": "Bearer test-secret"})
            self.assertEqual(failure.exception.status, 307)
            self.assertNotIn("test-secret", str(failure.exception))
            self.assertEqual(calls, ["https://portal.example/config"])

    async def test_homeview_transport_bounds_timeout_without_holding_ingress(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow(_):
            started.set()
            await release.wait()

        with patch("homeview_checks.CHECK_TIMEOUT", 0.05):
            async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as remote:
                pending = asyncio.create_task(request_json(remote, "GET", "https://portal.example/config", {}))
                await started.wait()
                transport = httpx.ASGITransport(app=app.app, client=("172.30.32.2", 4567))
                async with httpx.AsyncClient(transport=transport, base_url="http://addon") as local:
                    response = await local.get("/health")
                    self.assertEqual(response.status_code, 200)
                with self.assertRaises(RequestFailure):
                    await pending

    async def test_ingress_ping_works(self):
        transport = httpx.ASGITransport(app=app.app, client=("172.30.32.2", 4567))
        async with httpx.AsyncClient(transport=transport, base_url="http://addon") as client:
            self.assertEqual((await client.get("/api/ping")).status_code, 200)

    async def test_proxy_has_no_private_debug_routes_and_health_is_minimal(self):
        routes = {route.path for route in app.proxy_app.routes}
        self.assertNotIn("/_hometunnel/upstream", routes)
        self.assertNotIn("/_hometunnel/last-status", routes)
        transport = httpx.ASGITransport(app=app.proxy_app, client=("192.0.2.47", 4567))
        async with httpx.AsyncClient(transport=transport, base_url="http://addon") as client:
            self.assertEqual((await client.get("/health")).json(), {"ok": True})

    async def test_portal_body_urls_and_proxy_diagnostics_never_escape(self):
        secret = "synthetic-canary-not-a-real-credential"
        url = f"https://user:{secret}@192.0.2.47/private/route?code={secret}"
        body = json.dumps({"unknown": secret, "route": "2001:db8::/48", "ip": "192.0.2.47"})
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(EventFormatter())
        with patch.object(app.LOG, "handlers", [handler]), patch.object(app.LOG, "propagate", False):
            app.log_upstream_result(url, 401, body)
            app.log_heartbeat_payload({secret: body})
        text = stream.getvalue()
        self.assertIn('"status":401', text)
        for value in (secret, url, "192.0.2.47", "2001:db8::/48", "private/route"):
            self.assertNotIn(value, text)
        app.record_proxy_status("/auth/authorize", status_code=401, source="upstream",
                                upstream_url=url, location=url, error=secret)
        self.assertNotIn(secret, json.dumps(app.proxy_diagnostics_snapshot()))

    async def test_resolver_fails_closed_when_only_mdns_is_available(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(app, "update_proxy_runtime_state"), patch.object(app, "load_options", return_value={}), patch.dict(app.os.environ, {}, clear=True):
            resolver = app.HomeAssistantUpstreamResolver(pathlib.Path(tmp) / "cache.json")
            seen = []
            def probe(candidate):
                seen.append(candidate)
                return ("homeassistant.local" in candidate, "synthetic")
            with patch.object(resolver, "_health_check", side_effect=probe), patch.object(app, "DATA_DIR", pathlib.Path(tmp)), patch.object(app, "NETBIRD_DIR", pathlib.Path(tmp) / "netbird"):
                with self.assertRaises(app.UpstreamResolutionError):
                    resolver.resolve(force=True)
            self.assertFalse(any("homeassistant.local" in candidate for candidate in seen))


if __name__ == "__main__":
    unittest.main()

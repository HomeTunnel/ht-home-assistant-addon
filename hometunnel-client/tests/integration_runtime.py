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
from unittest.mock import AsyncMock, patch

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
from homeview_catalog import CatalogError, MAX_ENTRIES, core_lists
from homeview_checks import RequestFailure, request_json
from homeview_config import parse_monitors



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
            with patch.object(app, "homeview", runtime), patch.object(app, "is_core_admin", new=AsyncMock(return_value=True)):
                local = httpx.ASGITransport(app=app.app, client=("172.30.32.2", 4567))
                overlay = httpx.ASGITransport(app=app.app, client=("192.0.2.47", 4567))
                headers = {"X-Homeview-UI": "1", "X-Remote-User-Id": "a" * 32}
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
                        "revision": response.json()["revision"],
                        "monitors": [{"kind": "ha_api", "label": "Home Assistant"}],
                    }
                    self.assertEqual((await client.post(path, json=enabled, headers=headers)).status_code, 400)
                    review = await client.post(path + "/preview", json=enabled, headers=headers)
                    self.assertEqual(review.status_code, 200, review.text)
                    confirmation = {"preview": review.json()["preview"]}
                    saved = await client.post(path, json=confirmation, headers=headers)
                    self.assertEqual(saved.status_code, 200, saved.text)
                    self.assertTrue(saved.json()["enabled"])
                    self.assertNotIn("test-credential", saved.text)
                    self.assertEqual((await client.post(path, json=confirmation, headers=headers)).status_code, 409)
                    off = await client.post(path, json={"enabled": False}, headers=headers)
                    self.assertFalse(off.json()["enabled"])

    async def test_first_sharing_preview_expires_after_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            state = {
                "portal_base_url": "https://portal.example", "home_id": "home-a",
                "device_id": "device", "device_token": "device-secret", "binding": {"binding_id": "binding-a"},
            }
            path = "/api/homeview/local"
            headers = {"X-Homeview-UI": "1", "X-Remote-User-Id": "a" * 32}
            runtime = HomeviewRuntime(pathlib.Path(directory) / "homeview.json", lambda: state)
            ingress = httpx.ASGITransport(app=app.app, client=("172.30.32.2", 4567))
            with patch.object(app, "homeview", runtime), patch.object(app, "is_core_admin", new=AsyncMock(return_value=True)):
                async with httpx.AsyncClient(transport=ingress, base_url="http://addon", headers=headers) as client:
                    home_a = (await client.get(path)).json()
                    preview_body = {"revision": home_a["revision"],
                                    "monitors": [{"kind": "ha_api", "label": "Home A only"}]}
                    review = await client.post(path + "/preview", json=preview_body)
                    self.assertEqual(review.status_code, 200, review.text)
                    state.update(home_id="home-b", binding={"binding_id": "binding-b"})
                    stale = await client.post(path, json={"preview": review.json()["preview"]})
                    self.assertEqual(stale.status_code, 409)
                    home_b = (await client.get(path)).json()
                    self.assertNotEqual(home_a["revision"], home_b["revision"])
                    self.assertFalse(home_b["enabled"])
                    self.assertNotIn("Home A only", str(home_b))
                    self.assertEqual((await client.post(path + "/preview", json=preview_body)).status_code, 409)
                    fresh = await client.post(path + "/preview", json={"revision": home_b["revision"],
                                                                      "monitors": [{"kind": "ha_api", "label": "Home B"}]})
                    self.assertEqual(fresh.status_code, 200)
                    confirmed = await client.post(path, json={"preview": fresh.json()["preview"]})
                    self.assertTrue(confirmed.json()["enabled"])

    async def test_homeview_ingress_checks_resolved_limits_on_review_and_save(self):
        from test_homeview import pairing

        with tempfile.TemporaryDirectory() as directory:
            runtime = HomeviewRuntime(pathlib.Path(directory) / "homeview.json", pairing)
            devices = [{"id": f"device-{i}", "name": "Identical device name"} for i in range(6)]
            entities = [{"id": f"entity-{i}", "device_id": f"device-{i % 6}", "entity_id": f"sensor.item_{i}"}
                        for i in range(7)]
            states = [{"entity_id": row["entity_id"], "state": "85",
                       "attributes": {"device_class": "battery", "unit_of_measurement": "%"}} for row in entities]
            runtime.catalog.fetch = AsyncMock(return_value=(devices, entities, states))
            ingress = httpx.ASGITransport(app=app.app, client=("172.30.32.2", 4567))
            headers = {"X-Homeview-UI": "1", "X-Remote-User-Id": "a" * 32}
            path = "/api/homeview/local"
            with patch.object(app, "homeview", runtime), patch.object(app, "is_core_admin", new=AsyncMock(return_value=True)):
                async with httpx.AsyncClient(transport=ingress, base_url="http://addon", headers=headers) as client:
                    initial = (await client.get(path)).json()
                    self.assertEqual((initial["maxDevices"], initial["maxTcpServices"], initial["maxMonitors"]), (5, 3, 50))
                    page = (await client.get(path + "/discovery")).json()
                    keys = {item["hint"]: item["key"] for item in page["items"]}

                    def entity(index, kind="entity_availability"):
                        return {"key": keys[f"sensor.item_{index}"], "kind": kind}

                    tcp = [{"kind": "tcp_service", "label": f"Local service {i}", "ip": "192.168.1.50", "port": 8000 + i}
                           for i in range(4)]
                    ha = {"kind": "ha_api", "label": "Core"}

                    async def review(rows, revision=initial["revision"]):
                        return await client.post(path + "/preview", json={"revision": revision, "monitors": rows})

                    five = [entity(i) for i in range(5)]
                    for rows, error in ((five + [entity(5)], "device_limit"), (tcp, "tcp_limit"),
                                        ([{**tcp[0], "ip": "203.0.113.1"}], "invalid_settings")):
                        denied = await review([ha, *rows])
                        self.assertEqual((denied.status_code, denied.json()["error"]), (400, error))

                    # Availability and a value share a slot. Two entities on the same device do too.
                    at_capacity = [ha, *five, entity(6), entity(0, "battery_percent"), *tcp[:3]]
                    allowed = await review(at_capacity)
                    self.assertEqual(allowed.status_code, 200, allowed.text)
                    self.assertNotIn("sensor.item_", allowed.text)

                    # Simulate a pending confirmation resolved before the quota check was added.
                    token = allowed.json()["preview"]
                    pending = runtime.previews[token]
                    extra = parse_monitors([{"kind": "entity_availability", "label": "Extra sensor",
                                             "entity": "sensor.item_5", "registryId": "entity-5", "deviceId": "device-5"}],
                                           v2=True)
                    for additions, error in ((extra, "device_limit"), (parse_monitors(tcp[3:], v2=True), "tcp_limit")):
                        runtime.previews[token] = (*pending[:4], pending[4] + additions, pending[5])
                        denied = await client.post(path, json={"preview": token})
                        self.assertEqual((denied.status_code, denied.json()["error"]), (400, error))
                        self.assertFalse(runtime.view()["enabled"])

                    allowed = await review(at_capacity)
                    saved = (await client.post(path, json={"preview": allowed.json()["preview"]})).json()
                    device_rows = [m for m in saved["monitors"] if "selector" in m]
                    self.assertEqual(len({m["deviceSlot"] for m in device_rows}), 5)
                    self.assertEqual({m["hint"] for m in device_rows}, {f"sensor.item_{i}" for i in (0, 1, 2, 3, 4, 6)})
                    retained = [{"saved": m["id"], "kind": m["kind"], "label": m["label"]} for m in device_rows
                                if m["selector"] != keys["sensor.item_4"]]
                    for draft, status in (([ha, *retained, entity(4), entity(5)], 400),
                                          ([ha, *retained, entity(5)], 200)):
                        result = await review(draft, saved["revision"])
                        self.assertEqual(result.status_code, status, result.text)
                    updated = (await client.post(path, json={"preview": result.json()["preview"]})).json()
                    self.assertTrue({m["saved"] for m in retained} <= {m["id"] for m in updated["monitors"]})

    async def test_homeview_uses_core_admin_and_rejects_spoofed_identity(self):
        path = "/api/homeview/local"
        headers = {"X-Homeview-UI": "1", "X-Remote-User-Id": "a" * 32, "X-Remote-User-Groups": "system-admin"}
        deny = AsyncMock(return_value=False)
        with patch.object(app, "is_core_admin", new=deny):
            for source in ("127.0.0.1", "172.30.32.2"):
                transport = httpx.ASGITransport(app=app.app, client=(source, 9999))
                async with httpx.AsyncClient(transport=transport, base_url="http://addon") as client:
                    self.assertEqual((await client.get(path, headers=headers)).status_code, 403)
                    self.assertEqual((await client.get(path + "/discovery", headers={"X-Homeview-UI": "1"})).status_code, 403)
            deny.assert_awaited_once_with("a" * 32)

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
            runtime.apply({"enabled": True, "revision": runtime.view()["revision"], "monitors": [{"kind": "ha_api", "label": "Home Assistant"}]})
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

    async def test_supervisor_websocket_is_fixed_and_limits_inventory_without_truncation(self):
        events = []

        class CoreConnection:
            def __init__(self, url, **kwargs):
                self.assert_options(url, kwargs)
                self.frames = iter([
                    {"type": "auth_required"},
                    {"type": "auth_ok"},
                    {"type": "result", "id": 1, "success": True, "result": [None] * (MAX_ENTRIES + 1)},
                ])

            @staticmethod
            def assert_options(url, options):
                assert url == "ws://supervisor/core/websocket"
                assert options["proxy"] is None and options["max_queue"] == 1
                assert options["max_size"] > 65536

            async def __aenter__(self):
                redirect = ValueError("redirect")
                assert self.process_redirect(redirect) is redirect
                return self

            async def __aexit__(self, *_):
                return None

            async def recv(self):
                return json.dumps(next(self.frames))

            async def send(self, data):
                events.append(json.loads(data))

        with patch("websockets.asyncio.client.connect", CoreConnection):
            with self.assertRaisesRegex(CatalogError, "inventory_too_large"):
                await core_lists(("get_states",), "local-token")
            with self.assertRaisesRegex(ValueError, "unexpected_core_command"):
                await core_lists(("call_service",), "local-token")
        self.assertEqual(events, [
            {"type": "auth", "access_token": "local-token"},
            {"type": "get_states", "id": 1},
        ])

    async def test_homeview_v2_activation_and_tcp_only_report_use_negotiated_routes(self):
        fixture_dir = pathlib.Path(__file__).with_name("fixtures") / "homeview_v2" / "fixtures"
        inactive = json.loads((fixture_dir / "configBeforeActivation.json").read_text())
        active = json.loads((fixture_dir / "config.json").read_text())
        ack = threading.Event()
        seen = []

        def response(body, version=None):
            headers = {"X-Homeview-Version": str(version)} if version else {}
            return httpx.Response(200, headers=headers, stream=httpx.ByteStream(json.dumps(body).encode()))

        async def route(request):
            path = request.url.path
            seen.append((request.method, path, request.headers.get("x-homeview-version")))
            if request.url.host == "supervisor":
                self.assertEqual(request.headers.get("authorization"), "Bearer supervisor-local")
                self.assertEqual(path, "/network/info")
                return response({"result": "ok", "data": {}})
            self.assertEqual(request.headers.get("authorization"), "Bearer device-local")
            self.assertEqual(request.headers.get("x-homeview-binding-id"), "test-binding")
            self.assertEqual(request.headers.get("x-homeview-version"), "2")
            self.assertNotIn("192.168.1.40", request.content.decode())
            self.assertNotIn("supervisor-local", request.content.decode())
            if path.endswith("/config"):
                return response(inactive, 2)
            document = json.loads(request.content)
            if path.endswith("/activate"):
                self.assertEqual(document["activationGeneration"], "pair-grant-1")
                self.assertEqual(document["requestId"], committed.revision)
                return response({**active, "manifestRevision": 0, "session": None}, 2)
            if path.endswith("/monitors"):
                self.assertEqual(document["monitors"], [{"id": committed.monitors[0].id, "kind": "tcp_service", "label": "Camera"}])
                return response({**active, "session": {**active["session"], "bootId": document["bootId"]}}, 2)
            if path.endswith("/reports"):
                self.assertNotIn("entityApiStatus", document)
                self.assertEqual(document["observations"][0]["reason"], "check_failed")
                reply = json.loads((fixture_dir / "reportResponse.json").read_text())
                ack.set()
                return response(reply, 2)
            raise AssertionError("unexpected route")

        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"SUPERVISOR_TOKEN": "supervisor-local"}):
            state = {
                "portal_base_url": "https://portal.example", "home_id": "home", "device_id": "device",
                "device_token": "device-local", "binding": {"binding_id": "test-binding"},
                "netbird": {"connected": False},
            }
            runtime = HomeviewRuntime(pathlib.Path(directory) / "homeview.json", lambda: state)
            identity = runtime.identity()
            initial = runtime.settings.get(identity, for_preview=True)
            runtime.reporter.key = (identity, initial.revision)
            runtime.reporter.accept_config(inactive)
            review = await runtime.preview("admin", {"revision": initial.revision, "monitors": [
                {"kind": "tcp_service", "label": "Camera", "ip": "192.168.1.40", "port": 554}
            ]})
            runtime.confirm("admin", review["preview"])
            committed = runtime.settings.get(identity)
            create = httpx.AsyncClient
            with patch("homeview.httpx.AsyncClient", side_effect=lambda **kwargs: create(transport=httpx.MockTransport(route), **kwargs)):
                try:
                    runtime.start()
                    self.assertTrue(await asyncio.to_thread(ack.wait, 2), seen)
                finally:
                    runtime.stop()
                    await asyncio.to_thread(runtime.thread.join, 2)
        self.assertEqual([item[1].split("/")[-1] for item in seen], ["config", "activate", "monitors", "info", "reports"])

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

"""Run separately from stub-based unit tests with installed runtime dependencies."""
import asyncio
import io
import json
import logging
import pathlib
import sys
import tempfile
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


class RuntimeSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_overlay_cannot_spoof_ingress_with_forwarded_headers(self):
        transport = httpx.ASGITransport(app=app.app, client=("192.0.2.47", 4567))
        async with httpx.AsyncClient(transport=transport, base_url="http://addon") as client:
            for path in ("/api/status", "/api/pairing/reset", "/api/auth/start"):
                response = await client.post(path, headers={"X-Forwarded-For": "172.30.32.2"})
                self.assertEqual(response.status_code, 403)
            self.assertEqual((await client.get("/health")).status_code, 200)

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

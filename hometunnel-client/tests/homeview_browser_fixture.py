"""Serve real ingress and Homeview routes on loopback with synthetic Core data."""
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import uvicorn
from starlette.responses import Response

from integration_runtime import app
from homeview import HomeviewRuntime, parse_config
from homeview_catalog import CatalogError
from test_homeview import pairing
from test_homeview_v2 import fixture


def main():
    devices = [{"id": f"device-{i}", "name": name} for i, name in enumerate(
        ("Entry sensor", "Room 2", "Room 3", "Room 4", "Room 5", "router.local"), 1)]
    inventory = [
        (1, "binary_sensor.contact", {"device_class": "door", "friendly_name": "A Contact"}, "off"),
        (1, "sensor.battery", {"device_class": "battery", "unit_of_measurement": "%",
                               "friendly_name": "B Battery"}, "72"),
        (1, "sensor.humidity", {"device_class": "humidity", "friendly_name": "Humidity"}, "48"),
        (1, "sensor.temperature", {"device_class": "temperature", "friendly_name": "Temperature"}, "21"),
        *((1, f"light.filler_{i:02}", {}, "off") for i in range(42)),
        *((i, f"light.room_{i}", {}, "off") for i in range(2, 7)),
    ]
    registry = [{"id": f"registry-{i}", "device_id": f"device-{device}", "entity_id": entity}
                for i, (device, entity, _, _) in enumerate(inventory)]
    states = [{"entity_id": entity, "state": value, "attributes": attributes}
              for _, entity, attributes, value in inventory]
    paired = pairing()
    control = {"time": 0, "down": False, "reads": 0}

    async def fetch(_):
        control["reads"] += 1
        if control["down"]:
            raise CatalogError("core_unavailable")
        return devices, registry, states

    @app.app.post("/_test/homeview")
    async def control_fixture(change: dict):
        control["time"] += change.get("advance", 0)
        control["down"] = change.get("down", control["down"])
        if "name" in change:
            devices[0]["name"] = change["name"]
        if "savedLabel" in change:
            path = runtime.settings.path
            settings = json.loads(path.read_text(encoding="utf-8"))
            monitor = next(row for row in settings["monitors"] if row.get("entity") == "binary_sensor.contact")
            monitor["label"] = change["savedLabel"]
            path.write_text(json.dumps(settings), encoding="utf-8")
        if change.get("repair"):
            paired.update(home_id="new-home", binding={"binding_id": "new-binding"})
        return control

    async def ingress(scope, receive, send):
        if scope["type"] == "http":
            path = scope["path"]
            if path not in ("/", "/homeview.js", "/_test/homeview") and not path.startswith("/api/homeview/local"):
                await Response(status_code=404)(scope, receive, send)
                return
            scope = {**scope, "client": ("172.30.32.2", 4567),
                     "headers": [*scope["headers"], (b"x-remote-user-id", b"a" * 32)]}
        await app.app(scope, receive, send)

    with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
        runtime = HomeviewRuntime(Path(directory) / "homeview.json", lambda: paired, lambda: control["time"])
        runtime.catalog.fetch = fetch
        runtime.reporter.key = (runtime.identity(), runtime.view()["revision"])
        runtime.reporter.accept_config(parse_config(fixture("config")))
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        print(listener.getsockname()[1], flush=True)
        with patch.object(app, "homeview", runtime), patch.object(app, "is_core_admin", new=AsyncMock(return_value=True)):
            config = uvicorn.Config(ingress, lifespan="off", proxy_headers=False, access_log=False, log_level="error")
            uvicorn.Server(config).run(sockets=[listener])


if __name__ == "__main__":
    main()

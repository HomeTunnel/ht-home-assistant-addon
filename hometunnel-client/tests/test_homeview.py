from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rootfs/opt/hometunnel"))
# Production httpx is only needed by the transport. The unit suite uses the
# same dependency stubs as the other add-on tests.
import test_client_recovery_state  # noqa: F401

from heartbeat_payload import build_heartbeat_payload
from homeview import MAX_SEQUENCE, HomeviewRuntime, Portal, Reporter, parse_config
from homeview_checks import Collector, RequestFailure, entity_observation, lan_boundary, observation, safe_route, safe_target, stamp, tcp_probe
from homeview_config import Identity, Settings, parse_monitors, portal_origin

FIXTURES = Path(__file__).with_name("fixtures") / "homeview_v1"
T = datetime(2026, 11, 24, 19, 12, tzinfo=timezone.utc)
IDENTITY = Identity("https://portal.example", "home", "device", "binding", "test-device-secret")
LAN = {
    "interfaces": [{
        "interface": "eth0", "type": "ethernet", "primary": True, "enabled": True, "connected": True,
        "ipv4": {"address": ["192.168.5.10/23"], "gateway": "192.168.5.1", "nameservers": ["192.168.5.2"]},
    }],
    "docker": {"address": "172.30.32.0/23", "gateway": "172.30.32.1"},
}
MONITORS = parse_monitors([
    {"id": "ha", "kind": "ha_api", "label": "Home Assistant"},
    {"id": "camera", "kind": "tcp_service", "label": "Camera port", "ip": "192.168.5.20", "port": 443},
    {"id": "door", "kind": "battery_percent", "label": "Front door battery", "entity": "sensor.door_power", "lowThreshold": 20},
], stored=True)


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def pairing():
    return {"portal_base_url": IDENTITY.origin, "device_id": IDENTITY.device,
            "home_id": IDENTITY.home, "device_token": IDENTITY.token,
            "binding": {"binding_id": IDENTITY.binding},
            "netbird": {"connected": False}}


def state(entity, value, cls="battery", unit="%", **extra):
    return {"entity_id": entity, "state": value,
            "attributes": {"unit_of_measurement": unit, "device_class": cls, "api_key": "PRIVATE_ATTR"},
            **extra}


class ConfigurationTests(unittest.TestCase):
    def test_opaque_ids_persist_for_same_target_and_rotate_for_changed_target(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "settings.json"
            settings = Settings(p)
            rows = [{k: v for k, v in m.local().items() if k != "id"} for m in MONITORS]
            self.assertIsNone(settings.get(IDENTITY))
            preview = settings.get(IDENTITY, for_preview=True)
            self.assertFalse(preview.enabled)
            saved = settings.apply(IDENTITY, {"enabled": True, "revision": preview.revision, "monitors": rows})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(IDENTITY.token, p.read_text())
            self.assertEqual(Settings(p).get(IDENTITY), saved)
            rows[1]["label"] = "New label"
            rows[2]["entity"] = "sensor.other_power"
            edited = settings.apply(IDENTITY, {"enabled": True, "revision": saved.revision, "monitors": rows})
            self.assertEqual(edited.monitors[1].id, saved.monitors[1].id)
            self.assertNotEqual(edited.monitors[2].id, saved.monitors[2].id)
            with self.assertRaisesRegex(ValueError, "selection_changed"):
                settings.apply(IDENTITY, {"enabled": True, "revision": saved.revision, "monitors": rows})

    def test_local_disable_persists_until_acknowledged_and_repair_clears(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "settings.json"
            current = pairing()
            runtime = HomeviewRuntime(p, lambda: current)
            runtime.apply({"enabled": True, "revision": runtime.view()["revision"], "monitors": [{"kind": "ha_api", "label": "Home Assistant"}]})
            runtime.apply({"enabled": False})
            self.assertEqual(runtime.view()["status"], "stopping")
            stored = Settings(p).get(IDENTITY)
            self.assertFalse(stored.enabled)
            self.assertTrue(stored.disable_pending)
            runtime.settings.acknowledge_disable(IDENTITY, stored.revision)
            self.assertEqual(runtime.view()["status"], "off")
            runtime.clear()
            self.assertFalse(runtime.view()["paired"])
            self.assertFalse(p.exists())
            current["binding"]["binding_id"] = "another"
            self.assertTrue(runtime.view()["paired"])
            self.assertFalse(runtime.view()["enabled"])

    def test_scope_change_discards_saved_selections(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "settings.json"
            settings = Settings(p)
            preview = settings.get(IDENTITY, for_preview=True)
            settings.apply(IDENTITY, {"enabled": True, "revision": preview.revision, "monitors": [{"kind": "ha_api", "label": "HA"}]})
            self.assertIsNone(settings.get(Identity(IDENTITY.origin, "different-home", IDENTITY.device, IDENTITY.binding, IDENTITY.token)))
            self.assertFalse(p.exists())

    def test_origins_and_local_addresses_fail_closed(self):
        for value in ("http://portal.example", "https://user@portal.example", "https://portal.example/x",
                      "https://127.0.0.1", "https://[::1]", "https://portal.example?x=1",
                      "https://portal.example:8443", "https://portal.example\\@else.example"):
            self.assertIsNone(portal_origin(value))
        self.assertEqual(portal_origin("https://portal.example:443/"), IDENTITY.origin)
        self.assertNotIn(IDENTITY.token, repr(IDENTITY))
        boundary = lan_boundary(LAN)
        self.assertTrue(safe_target("192.168.5.20", boundary))
        for ip in ("192.168.4.50", "192.168.5.0", "192.168.5.255", "192.168.5.1", "192.168.5.2",
                   "192.168.5.10", "172.30.32.2", "169.254.169.254", "127.0.0.1", "100.64.1.2",
                   "::ffff:192.168.5.20", "camera.local", "8.8.8.8"):
            self.assertFalse(safe_target(ip, boundary), ip)
        self.assertFalse(safe_target("192.168.5.20", lan_boundary({})))
        self.assertFalse(safe_route([{"dev": "wt0", "gateway": "172.30.32.1"}], "172.30.32.1"))
        self.assertFalse(safe_route([{"dev": "eth0", "gateway": "10.1.1.1"}], "172.30.32.1"))
        self.assertTrue(safe_route([{"dev": "eth0", "gateway": "172.30.32.1"}], "172.30.32.1"))


class MeasurementTests(unittest.IsolatedAsyncioTestCase):
    def test_battery_flags_percentages_and_sleeping_sensor(self):
        battery = MONITORS[2]
        old = T - timedelta(days=3)
        measured = entity_observation(battery, state(battery.entity, "17.5", last_reported=stamp(old)), T)
        self.assertEqual(measured["batteryPercent"], 17.5)
        self.assertEqual(measured["sourceReportedAt"], stamp(old))
        self.assertNotIn(battery.entity, repr(measured))
        self.assertNotIn("PRIVATE_ATTR", repr(measured))
        for invalid in ("NaN", "inf", "101", "-1", "bad"):
            self.assertEqual(entity_observation(battery, state(battery.entity, invalid), T)["reason"], "invalid_entity")
        self.assertEqual(entity_observation(battery, state(battery.entity, "2", unit="V"), T)["result"], "configuration_error")
        for kind, cls, yes, no in (
            ("battery_binary", "battery", "low", "normal"), ("entity_connectivity", "connectivity", "connected", "disconnected"),
        ):
            entity = "binary_sensor.example"
            monitor = parse_monitors([MONITORS[0].local(), {"id": "other", "kind": kind, "label": "Example", "entity": entity}], stored=True)[1]
            self.assertEqual(entity_observation(monitor, state(entity, "on", cls), T)["result"], yes)
            self.assertEqual(entity_observation(monitor, state(entity, "off", cls), T)["result"], no)
            self.assertEqual(entity_observation(monitor, state(entity, "unavailable", cls), T)["result"], "unknown")
        self.assertEqual(entity_observation(battery, state(battery.entity, "unknown"), T)["reason"], "no_signal")
        availability = parse_monitors([MONITORS[0].local(), {"id": "other", "kind": "entity_availability",
                                      "label": "Example", "entity": "light.example"}], stored=True)[1]
        self.assertEqual(entity_observation(availability, state(availability.entity, "unavailable"), T)["result"], "unavailable")
        self.assertEqual(entity_observation(availability, state(availability.entity, "off"), T)["result"], "available")

    async def test_ha_restart_and_missing_entity_do_not_block_safe_tcp(self):
        probe = AsyncMock(return_value=("responding", None))
        collector = Collector(object(), lambda: "LOCAL_SUPERVISOR_SECRET", probe)
        with patch("homeview_checks.request_json", new=AsyncMock(side_effect=[
            RequestFailure(503), {"result": "ok", "data": LAN},
            {"message": "API running."}, {"result": "ok", "data": LAN}, RequestFailure(404),
        ])) as request:
            first = await collector.collect(MONITORS, lambda: True)
            self.assertEqual([o["result"] for o in first], ["not_responding", "responding", "unknown"])
            self.assertEqual(request.await_count, 2)
            second = await collector.collect(MONITORS, lambda: True)
            self.assertEqual(second[0]["result"], "responding")
            self.assertEqual(second[2]["reason"], "entity_missing")
            self.assertEqual(probe.await_count, 2)
            self.assertTrue(all(call.args[1] == "GET" and call.args[2].startswith("http://supervisor/")
                                for call in request.await_args_list))
            self.assertNotIn("LOCAL_SUPERVISOR_SECRET", repr(first + second))

    async def test_failed_network_boundary_never_probes_target(self):
        probe = AsyncMock()
        collector = Collector(object(), lambda: "LOCAL_SUPERVISOR_SECRET", probe)
        with patch("homeview_checks.request_json", new=AsyncMock(side_effect=[
            {"message": "API running."}, RequestFailure(), state(MONITORS[2].entity, "25"),
        ])):
            observations = await collector.collect(MONITORS, lambda: True)
            self.assertEqual((observations[1]["result"], observations[1]["reason"]), ("unknown", "check_failed"))
            self.assertEqual(observations[2]["batteryPercent"], 25)
            probe.assert_not_awaited()

    async def test_known_excluded_address_is_rejected_without_probing(self):
        probe = AsyncMock()
        collector = Collector(object(), lambda: "local-token", probe)
        monitors = parse_monitors([MONITORS[0].local(), {**MONITORS[1].local(), "ip": "192.168.5.1"}], stored=True)
        with patch("homeview_checks.request_json", new=AsyncMock(side_effect=[
            {"message": "API running."}, {"result": "ok", "data": LAN},
        ])):
            _, tcp = await collector.collect(monitors, lambda: True)
        self.assertEqual((tcp["result"], tcp["reason"]), ("configuration_error", "unsafe_target"))
        probe.assert_not_awaited()

    async def test_route_lookup_failure_and_rejected_route_do_not_connect(self):
        for status, output, expected in (
            (1, b"", ("unknown", "check_failed")),
            (0, b"invalid", ("unknown", "check_failed")),
            (0, b"[]", ("unknown", "check_failed")),
            (0, b'[{"dev":"wt0"}]', ("configuration_error", "unsafe_target")),
        ):
            with self.subTest(status=status, output=output):
                process = Mock(returncode=status, communicate=AsyncMock(return_value=(output, b"")))
                with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)), patch("socket.socket") as connect:
                    self.assertEqual(await tcp_probe("192.168.5.20", 443, "172.30.32.1"), expected)
                    connect.assert_not_called()


class FakePortal:
    def __init__(self):
        self.value = {**fixture("config"), "session": None, "manifestRevision": 0}
        self.manifests = []
        self.reports = []
        self.manifest_status = None
        self.lose_manifest_ack = False
        self.lose_report_ack = False
        self.last_manifest = self.last_report = None

    async def config(self):
        return parse_config(json.loads(json.dumps(self.value)))

    async def manifest(self, body):
        self.manifests.append(body)
        if self.manifest_status is not None:
            raise RequestFailure(self.manifest_status)
        args = json.loads(body)
        if body != self.last_manifest:
            if args["expectedRevision"] != self.value["manifestRevision"]:
                raise RequestFailure(409)
            self.last_manifest = body
            new = self.value["manifestRevision"] + 1
            session = {"id": f"session-{new}", "bootId": args["bootId"], "nextSequence": 1} if args["enabled"] else None
            self.value = {**self.value, "manifestRevision": new, "session": session}
        if self.lose_manifest_ack:
            self.lose_manifest_ack = False
            raise RequestFailure()
        return await self.config()

    async def report(self, body):
        self.reports.append(body)
        report = json.loads(body)
        if body != self.last_report:
            self.assert_sequence(report)
            self.last_report = body
            self.value["session"]["nextSequence"] = report["sequence"] + 1
        if self.lose_report_ack:
            self.lose_report_ack = False
            raise RequestFailure()

    def assert_sequence(self, report):
        if report["sequence"] < self.value["session"]["nextSequence"]:
            raise RequestFailure(409)


class ReportingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.seconds = 0
        self.portal = FakePortal()
        self.now = lambda: T + timedelta(seconds=self.seconds)
        self.reporter = Reporter(lambda: self.seconds, lambda: stamp(self.now()), lambda: 0)
        self.selection = type("Selection", (), {"revision": "local-revision", "enabled": True,
                                                "disable_pending": False, "monitors": MONITORS})()
        self.collector = AsyncMock()
        self.collector.collect.side_effect = self.samples

    async def samples(self, monitors, allowed):
        values = [observation(monitors[0], "responding", now=self.now()),
                  observation(monitors[1], "not_responding", now=self.now()),
                  entity_observation(monitors[2], state(monitors[2].entity, "17"), self.now())]
        return values if allowed() else None

    async def step(self):
        await self.reporter.step(self.selection, IDENTITY, self.portal, self.collector, lambda: True, lambda: None)

    async def test_registered_manifest_matches_fixture_and_report_is_exactly_allowlisted(self):
        # No network or peer state is needed after durable pairing.
        self.assertEqual(Identity.read(pairing()), IDENTITY)
        with patch("homeview.new_id", return_value="request-1"):
            self.reporter.boot = "boot-1"
            await self.step()
        self.assertEqual(json.loads(self.portal.manifests[0]), fixture("manifestRequest"))
        self.assertEqual(json.loads(self.portal.reports[0]), fixture("reportRequest"))
        self.assertNotIn(b"test-device-secret", self.portal.reports[0])
        self.assertNotIn(b"sensor.door_power", self.portal.manifests[0])
        self.assertNotIn(b"192.168.5.20", self.portal.manifests[0])

    async def test_ambiguous_write_retries_identical_bytes_and_restart_rotates_session(self):
        self.portal.lose_manifest_ack = self.portal.lose_report_ack = True
        await self.step()
        self.assertFalse(self.portal.reports)
        self.seconds = 2
        await self.step()
        self.assertEqual(self.portal.manifests[0], self.portal.manifests[1])
        self.seconds = 6
        await self.step()
        self.assertEqual(self.portal.reports[0], self.portal.reports[1])
        self.assertEqual(self.reporter.next_sequence, 2)
        self.assertEqual(self.collector.collect.await_count, 1)
        old = self.reporter
        self.reporter = Reporter(lambda: self.seconds, lambda: stamp(self.now()), lambda: 0)
        self.seconds = 62
        await self.step()
        self.assertNotEqual(self.reporter.boot, old.boot)
        self.assertEqual(json.loads(self.portal.reports[-1])["sequence"], 1)
        self.assertNotEqual(json.loads(self.portal.reports[-1])["sessionId"], json.loads(self.portal.reports[0])["sessionId"])

    async def test_manifest_400_blocks_until_corrected_selection_is_confirmed(self):
        with tempfile.TemporaryDirectory() as directory, self.assertNoLogs(level="WARNING"):
            paired = pairing()
            paired["route"] = {"current_endpoint": "http://192.0.2.41:80", "target_port": 80}
            heartbeat = build_heartbeat_payload(paired["netbird"], paired)
            runtime = HomeviewRuntime(Path(directory) / "homeview.json", lambda: paired)
            runtime.reporter = self.reporter
            rows = [{"kind": "ha_api", "label": "Synthetic core label"}]
            preview = await runtime.preview("admin", {"revision": runtime.view()["revision"], "monitors": rows})
            runtime.confirm("admin", preview["preview"])
            selection = runtime.settings.get(IDENTITY)
            self.reporter.key = (IDENTITY, selection.revision)
            self.reporter.accept_config(await self.portal.config())
            self.reporter.registered = ("generation", 1, "stale-session")
            self.reporter.next_sequence = MAX_SEQUENCE + 1
            self.reporter.report_pending = (0, MAX_SEQUENCE, b"stale report")
            self.portal.config = AsyncMock(wraps=self.portal.config)
            self.portal.manifest_status = 400
            self.collector.collect.side_effect = lambda monitors, _: [
                observation(monitors[0], "responding", now=self.now())
            ]

            async def step():
                await self.reporter.step(runtime.settings.get(IDENTITY), IDENTITY, self.portal,
                                         self.collector, lambda: True, lambda: None)

            for self.seconds in (0, 2, 6, 60, 120, 180):
                await step()
                self.assertEqual(runtime.view()["status"], "review_settings")
                self.assertIsNone(self.reporter.manifest_pending)
                self.assertIsNone(self.reporter.report_pending)
                self.assertIsNone(self.reporter.registered)
                self.assertEqual(self.reporter.lease, 0)
            self.assertEqual(self.portal.config.await_count, 3)
            self.assertEqual(len(self.portal.manifests), 1)
            self.assertFalse(self.portal.reports)
            self.collector.collect.assert_not_awaited()

            rows[0]["label"] = "Ⓗome interface"
            preview = await runtime.preview("admin", {"revision": selection.revision, "monitors": rows})
            self.portal.manifest_status = None
            await step()
            self.assertEqual(len(self.portal.manifests), 1)
            runtime.confirm("admin", preview["preview"])
            corrected = runtime.settings.get(IDENTITY)
            self.assertNotEqual(corrected.revision, selection.revision)
            self.assertEqual(corrected.monitors[0].id, selection.monitors[0].id)
            await step()
            self.assertEqual(runtime.view()["status"], "reporting")
            self.assertEqual(len(self.portal.manifests), 2)
            manifest = json.loads(self.portal.manifests[-1])
            self.assertEqual(manifest["monitors"][0]["label"], "Ⓗome interface")
            self.assertEqual(json.loads(self.portal.reports[0])["sequence"], 1)
            self.collector.collect.assert_awaited_once()
            self.assertEqual(build_heartbeat_payload(paired["netbird"], paired), heartbeat)

    async def test_manifest_400_does_not_block_disable(self):
        self.portal.manifest_status = 400
        await self.step()
        self.assertEqual(self.reporter.status, "review_settings")

        self.portal.manifest_status = None
        self.selection.revision = "disabled-revision"
        self.selection.enabled = False
        self.selection.disable_pending = True
        acknowledge = Mock()
        await self.reporter.step(self.selection, IDENTITY, self.portal, self.collector, lambda: True, acknowledge)
        acknowledge.assert_called_once()
        self.assertEqual(self.reporter.status, "off")
        self.assertEqual(json.loads(self.portal.manifests[-1])["monitors"], [])
        self.assertFalse(self.portal.reports)
        self.collector.collect.assert_not_awaited()

    async def test_repair_during_blocked_config_poll_clears_the_block(self):
        self.portal.manifest_status = 400
        await self.step()
        self.assertEqual(self.reporter.status, "review_settings")
        started, release = asyncio.Event(), asyncio.Event()
        current = True
        config = self.portal.config

        async def poll():
            started.set()
            await release.wait()
            return await config()

        self.seconds = 60
        self.portal.config = poll
        task = asyncio.create_task(self.reporter.step(
            self.selection, IDENTITY, self.portal, self.collector, lambda: current, lambda: None,
        ))
        await asyncio.wait_for(started.wait(), 1)
        current = False
        release.set()
        await task
        self.assertEqual(len(self.portal.manifests), 1)
        self.assertEqual(self.reporter.lease, 0)
        self.collector.collect.assert_not_awaited()

        # The same selection revision under a different pairing has its own state.
        other = replace(IDENTITY, home="other-home", binding="other-binding")
        other_portal = FakePortal()
        await self.reporter.step(self.selection, other, other_portal, self.collector, lambda: True, lambda: None)
        self.assertEqual(self.reporter.status, "reporting")
        self.assertEqual(len(other_portal.reports), 1)

    async def test_stale_in_flight_manifest_400_cannot_block_replacement(self):
        started, release = asyncio.Event(), asyncio.Event()
        current = True

        async def reject(_):
            started.set()
            await release.wait()
            raise RequestFailure(400)

        manifest = self.portal.manifest
        self.portal.manifest = reject
        task = asyncio.create_task(self.reporter.step(
            self.selection, IDENTITY, self.portal, self.collector, lambda: current, lambda: None,
        ))
        await asyncio.wait_for(started.wait(), 1)
        current = False
        release.set()
        await task
        self.assertFalse(self.reporter.manifest_rejected)
        self.collector.collect.assert_not_awaited()

        self.portal.manifest = manifest
        self.selection.revision = "confirmed-replacement"
        await self.step()
        self.assertEqual(self.reporter.status, "reporting")
        self.assertEqual(len(self.portal.reports), 1)

    async def test_manifest_transient_failures_and_conflict_remain_retryable(self):
        for status, identical in ((429, True), (503, True), (409, False)):
            with self.subTest(status=status):
                self.setUp()
                self.portal.manifest_status = status
                await self.step()
                self.assertEqual(self.reporter.status, "waiting_portal")
                self.seconds = 1
                await self.step()
                self.assertEqual(len(self.portal.manifests), 1)
                self.portal.manifest_status = None
                self.seconds = 2
                await self.step()
                self.assertEqual(self.portal.manifests[0] == self.portal.manifests[1], identical)
                self.assertEqual(len(self.portal.reports), 1)

    async def test_config_and_report_400_keep_generic_retries(self):
        config, report = self.portal.config, self.portal.report
        self.portal.config = AsyncMock(side_effect=RequestFailure(400))
        await self.step()
        self.assertEqual(self.reporter.status, "waiting_portal")
        self.portal.config = config
        self.portal.report = AsyncMock(side_effect=RequestFailure(400))
        self.seconds = 2
        await self.step()
        self.assertEqual(self.reporter.status, "waiting_portal")
        pending = self.portal.report.call_args.args[0]
        self.portal.report = report
        self.seconds = 6
        await self.step()
        self.assertEqual(self.portal.reports, [pending])
        self.assertEqual(self.reporter.next_sequence, 2)
        self.assertEqual(len(self.portal.manifests), 1)
        self.collector.collect.assert_awaited_once()

    async def test_expired_lease_or_revoked_config_prevents_further_probes_and_reports(self):
        await self.step()
        self.seconds = 61
        self.portal.value = {**self.portal.value, "enabled": False, "consentGeneration": None,
                             "manifestRevision": 0, "session": None}
        await self.step()
        self.assertEqual(self.reporter.status, "portal_off")
        self.assertEqual(self.reporter.lease, 0)
        self.assertEqual(self.collector.collect.await_count, 1)
        self.seconds = 122
        self.portal.value = {**fixture("config"), "session": None, "manifestRevision": 0}

        async def expiry(monitors, allowed):
            self.seconds += 181
            self.assertFalse(allowed())
            return await self.samples(monitors, allowed)
        self.collector.collect.side_effect = expiry
        await self.step()
        self.assertEqual(len(self.portal.reports), 1)

    async def test_rejected_or_expired_reports_do_not_reuse_sequence_or_backfill(self):
        await self.step()
        self.seconds = 60
        saved = self.portal.report
        self.portal.report = AsyncMock(side_effect=RequestFailure(422))
        await self.step()
        self.assertEqual(self.reporter.status, "clock_error")
        self.assertEqual(self.reporter.next_sequence, 3)
        self.assertIsNone(self.reporter.report_pending)
        self.portal.report = saved
        self.seconds = 120
        await self.step()
        self.assertEqual(json.loads(self.portal.reports[-1])["sequence"], 3)

    async def test_local_disable_sends_empty_manifest_and_never_collects(self):
        await self.step()
        self.selection.revision = "disabled-revision"
        self.selection.enabled = False
        self.selection.disable_pending = True
        await self.step()
        disabled = json.loads(self.portal.manifests[-1])
        self.assertFalse(disabled["enabled"])
        self.assertEqual(disabled["monitors"], [])
        self.assertEqual(self.collector.collect.await_count, 1)

    async def test_request_bearer_and_binding_are_only_sent_to_paired_portal(self):
        with patch("homeview.request_json", new=AsyncMock(side_effect=[fixture("config"), fixture("reportResponse")])) as request:
            portal = Portal(object(), IDENTITY)
            await portal.config()
            await portal.report(b'{"schemaVersion":1}')
            for args in request.await_args_list:
                url, headers = args.args[2:4]
                self.assertTrue(url.startswith("https://portal.example/api/devices/device/homeview/"))
                self.assertEqual(headers["Authorization"], "Bearer " + IDENTITY.token)
                self.assertEqual(headers["X-Homeview-Binding-Id"], IDENTITY.binding)


if __name__ == "__main__":
    unittest.main()

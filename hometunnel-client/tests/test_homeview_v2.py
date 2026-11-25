from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from test_homeview import FakePortal, IDENTITY, MONITORS, T, pairing, state
from homeview import HomeviewRuntime, Reporter, parse_config
from homeview_catalog import Catalog, CatalogError, is_core_admin
from homeview_checks import Collector, RequestFailure, entity_observation, stamp
from homeview_config import Settings, parse_monitors


def fixture(name):
    return json.loads((Path(__file__).with_name("fixtures") / "homeview_v2" / "fixtures" / f"{name}.json").read_text())


DEVICES = [
    {"id": "front", "name": "Entry", "identifiers": ["secret-serial"]},
    {"id": "hall", "name": "Entry"},
    {"id": "service", "name": "Calendar", "entry_type": "service"},
    {"id": "disabled", "name": "Disabled", "disabled_by": "user"},
]
ROWS = [
    ("contact-id", "front", "binary_sensor.front", "off", "door"),
    ("light-id", "hall", "light.hall", "off", ""),
    ("switch-id", "hall", "switch.hall", "on", ""),
    ("missing-id", "front", "binary_sensor.missing", None, "door"),
    ("unknown-id", "front", "binary_sensor.unknown", "unknown", "door"),
    ("away-id", "front", "binary_sensor.away", "unavailable", "door"),
    ("service-id", "service", "binary_sensor.service", "off", "door"),
    ("disabled-id", "disabled", "binary_sensor.disabled", "off", "door"),
    ("floating-id", None, "binary_sensor.floating", "off", "door"),
]
REGISTRY = [{"id": key, "device_id": device, "entity_id": entity} for key, device, entity, _, _ in ROWS]
STATES = [
    state(entity, value, cls, friendly_name="Check") | {
        "attributes": {"device_class": cls, "friendly_name": "Check", "token": "private-attribute"}
    }
    for _, _, entity, value, cls in ROWS if value is not None
]
CONTACT = {
    "kind": "entity_contact", "entity": "binary_sensor.front", "registryId": "contact-id", "deviceId": "front", "label": "Front door",
}
AVAIL = {**CONTACT, "kind": "entity_availability"}


class CatalogTests(unittest.IsolatedAsyncioTestCase):
    async def test_usable_off_and_closed_entities_group_by_device_without_leaking_registry_data(self):
        catalog = Catalog(AsyncMock(return_value=(DEVICES, REGISTRY, STATES)))
        page = await catalog.page(IDENTITY.scope, "", 0)
        items = {row["hint"]: row for row in page["items"]}
        self.assertEqual(set(items), {"binary_sensor.front", "light.hall", "switch.hall"})
        self.assertEqual(items["binary_sensor.front"]["kind"], "entity_contact")
        self.assertEqual(items["light.hall"]["kind"], "entity_light")
        self.assertEqual(items["switch.hall"]["kind"], "entity_switch")
        self.assertNotEqual(items["binary_sensor.front"]["group"], items["light.hall"]["group"])
        self.assertEqual(items["light.hall"]["group"], items["switch.hall"]["group"])
        self.assertNotIn("contact-id", str(page))
        self.assertNotIn("secret-serial", str(page))
        self.assertNotIn("private-attribute", str(page))
        self.assertEqual(len((await catalog.page(IDENTITY.scope, "light.hall", 0))["items"]), 1)
        catalog.fetch.assert_awaited_once()

    async def test_large_inventory_is_paginated_and_cache_is_scoped_and_expires(self):
        rows = [{"id": f"id-{n}", "device_id": "front", "entity_id": f"light.item_{n:04}"} for n in range(900)]
        states = [state(row["entity_id"], "off") for row in rows]
        self.assertGreater(len(json.dumps(states)), 65536)
        clock = [0]
        catalog = Catalog(AsyncMock(return_value=(DEVICES, rows, states)), lambda: clock[0])
        first = await catalog.page(IDENTITY.scope, "", 0)
        second = await catalog.page(IDENTITY.scope, "", first["next"])
        self.assertEqual(len(first["items"]), 40)
        self.assertNotEqual(first["items"][0]["key"], second["items"][0]["key"])
        self.assertEqual((await catalog.page(IDENTITY.scope, "0899", 0))["items"][0]["hint"], "light.item_0899")
        catalog.fetch.assert_awaited_once()
        key = first["items"][0]["key"]
        self.assertIsNone(catalog.lookup(("other",), key))
        clock[0] = 61
        self.assertIsNone(catalog.lookup(IDENTITY.scope, key))
        await catalog.page(IDENTITY.scope, "", 0)
        self.assertEqual(catalog.fetch.await_count, 2)

    async def test_admin_uses_core_record_and_fails_closed(self):
        for args, verdict in [
            ({"group_ids": ["system-admin"]}, True),
            ({"group_ids": ["system-users"], "is_owner": True}, True),
            ({"group_ids": ["system-users"]}, False),
            ({"group_ids": ["system-admin"], "is_active": False}, False),
            ({"group_ids": ["system-admin"], "system_generated": True}, False),
        ]:
            users = [{"id": "requester", "is_active": True, "system_generated": False, **args}]
            with patch("homeview_catalog.core_lists", new=AsyncMock(return_value=[users])) as read:
                self.assertEqual(await is_core_admin("requester"), verdict)
                self.assertFalse(await is_core_admin("unverified"))
                self.assertEqual(read.call_args.args, (("config/auth/list",),))


class CollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_single_state_read_produces_both_signals_and_preserves_old_source_time(self):
        monitors = parse_monitors([AVAIL, CONTACT], v2=True)
        path = "binary_sensor.renamed"
        registry = AsyncMock(return_value={"contact-id": ("front", path)})
        collector = Collector(None, lambda: "token", registry=registry)
        old = stamp(T - timedelta(days=12))
        with patch("homeview_checks.request_json", new=AsyncMock(return_value=state(path, "off", "door", last_reported=old))) as read:
            values, evidence = await collector.collect_v2(monitors, lambda: True)
        read.assert_awaited_once()
        self.assertTrue(read.call_args.args[2].endswith("/states/" + path))
        self.assertEqual(registry.await_count, 2)
        self.assertEqual(evidence, "responding")
        self.assertEqual([row["result"] for row in values], ["available", "closed"])
        self.assertEqual(values[1]["sourceReportedAt"], old)
        self.assertNotIn("private", str(values))
        self.assertNotIn(path, str(values))
        self.assertEqual(monitors[0].entity_group, monitors[1].entity_group)
        self.assertEqual(monitors[0].device_group, monitors[1].device_group)
        self.assertNotIn("contact-id", str([m.manifest(2) for m in monitors]))

    async def test_absent_registry_identity_and_replacement_race_withhold_data(self):
        monitors = parse_monitors([CONTACT], v2=True)
        for snapshots, reads, reason in [
            ([{"replacement-id": ("front", CONTACT["entity"])}], 0, "entity_missing"),
            ([{"contact-id": ("hall", CONTACT["entity"])}], 0, "entity_missing"),
            ([{"contact-id": ("front", CONTACT["entity"])}, {"replacement-id": ("front", CONTACT["entity"])}], 1, "check_failed"),
        ]:
            with self.subTest(snapshots=snapshots):
                collector = Collector(None, lambda: "token", registry=AsyncMock(side_effect=snapshots))
                with patch("homeview_checks.request_json", new=AsyncMock(return_value=state(CONTACT["entity"], "on", "door"))) as read:
                    values, _ = await collector.collect_v2(monitors, lambda: True)
                self.assertEqual(read.await_count, reads)
                self.assertEqual(values[0]["reason"], reason)
                self.assertNotIn(values[0]["result"], ("open", "closed"))

    async def test_unavailable_unknown_missing_outage_and_denial_are_distinct(self):
        monitors = parse_monitors([AVAIL, CONTACT], v2=True)
        registry = AsyncMock(return_value={"contact-id": ("front", CONTACT["entity"])})
        collector = Collector(None, lambda: "token", registry=registry)
        for result, available, status, evidence in [
            (state(CONTACT["entity"], "unavailable", "door"), ("unavailable", None), ("unknown", "no_signal"), "responding"),
            (state(CONTACT["entity"], "unknown", "door"), ("unknown", "no_signal"), ("unknown", "no_signal"), "responding"),
            (RequestFailure(404), ("configuration_error", "entity_missing"), ("configuration_error", "entity_missing"), "responding"),
            (RequestFailure(503), ("unknown", "ha_api_unavailable"), ("unknown", "ha_api_unavailable"), "unavailable"),
            (RequestFailure(403), ("configuration_error", "permission_denied"), ("configuration_error", "permission_denied"), "unavailable"),
        ]:
            if isinstance(result, Exception):
                read = AsyncMock(side_effect=result)
            else:
                read = AsyncMock(return_value=result)
            with patch("homeview_checks.request_json", new=read):
                values, observed_evidence = await collector.collect_v2(monitors, lambda: True)
            self.assertEqual([(row["result"], row.get("reason")) for row in values], [available, status])
            self.assertEqual(observed_evidence, evidence)

    async def test_tcp_only_has_no_core_probe_or_entity_evidence(self):
        collector = Collector(None, lambda: "token", probe=AsyncMock(return_value=("responding", None)), registry=AsyncMock())
        with patch("homeview_checks.request_json", new=AsyncMock(side_effect=RequestFailure(503))) as read:
            values, evidence = await collector.collect_v2([MONITORS[1]], lambda: True)
        self.assertEqual(values[0]["reason"], "check_failed")
        self.assertIsNone(evidence)
        read.assert_awaited_once()
        self.assertTrue(read.call_args.args[2].endswith("/network/info"))
        collector.registry.assert_not_awaited()

    def test_light_switch_and_battery_use_only_allowlisted_types(self):
        for kind, entity in [("entity_light", "light.hall"), ("entity_switch", "switch.hall")]:
            monitor, = parse_monitors([{**CONTACT, "kind": kind, "entity": entity}], v2=True)
            for value in ("on", "off"):
                self.assertEqual(entity_observation(monitor, state(entity, value))["result"], value)
            self.assertEqual(entity_observation(monitor, state(entity, "private-value"))["reason"], "invalid_entity")
        binary, = parse_monitors([{**CONTACT, "kind": "battery_binary"}], v2=True)
        percent = MONITORS[2]
        self.assertEqual(entity_observation(binary, state(binary.entity, "on"))["result"], "low")
        self.assertEqual(entity_observation(binary, state(binary.entity, "off"))["result"], "normal")
        self.assertEqual(entity_observation(binary, state(binary.entity, "on", "battery_charging"))["reason"], "invalid_entity")
        self.assertEqual(entity_observation(percent, state(percent.entity, "18.5"))["batteryPercent"], 18.5)
        self.assertEqual(entity_observation(percent, state(percent.entity, "18.5", unit="V"))["reason"], "invalid_entity")


class SettingsAndProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_preview_does_not_select_siblings_and_binds_admin_and_pairing(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "homeview.json"
            identity = pairing()
            runtime = HomeviewRuntime(state_file, lambda: identity)
            runtime.catalog = Catalog(AsyncMock(return_value=(DEVICES, REGISTRY, STATES)))
            view = runtime.view()
            runtime.reporter.key = (IDENTITY, view["revision"])
            runtime.reporter.accept_config(parse_config(fixture("configBeforeActivation")))
            items = (await runtime.discover("binary_sensor.front", 0))["items"]
            self.assertEqual(len(items), 1)
            key = items[0]["key"]
            rows = [{"key": key, "kind": "entity_availability", "label": "Front door"},
                    {"key": key, "kind": "entity_contact", "label": "Front door"}]
            body = {"revision": view["revision"], "monitors": rows}
            preview = runtime.preview("admin", body)
            self.assertEqual(preview["monitors"], [{k: v for k, v in row.items() if k != "key"} for row in rows])
            with self.assertRaisesRegex(ValueError, "selection_changed"):
                runtime.confirm("someone-else", preview["preview"])
            preview = runtime.preview("admin", body)
            runtime.confirm("admin", preview["preview"])
            selection = Settings(state_file).get(IDENTITY)
            self.assertTrue(selection.enabled)
            self.assertEqual(selection.activation_generation, "pair-grant-1")
            self.assertEqual(len(selection.monitors), 2)
            original = selection.monitors[1]
            renamed = parse_monitors([{**CONTACT, "entity": "binary_sensor.new_name"}], selection.monitors, v2=True)[0]
            replacement = parse_monitors([{**CONTACT, "registryId": "different"}], selection.monitors, v2=True)[0]
            self.assertEqual(renamed.id, original.id)
            self.assertEqual(renamed.entity_group, original.entity_group)
            self.assertNotEqual(replacement.id, original.id)
            legacy = runtime.view()
            runtime.reporter.key = (IDENTITY, legacy["revision"])
            runtime.reporter.accept_config(parse_config(fixture("config")))
            active_preview = runtime.preview("admin", {"revision": legacy["revision"], "monitors": rows})
            identity["home_id"] = "different-home"
            with self.assertRaisesRegex(ValueError, "selection_changed"):
                runtime.confirm("admin", active_preview["preview"])

    async def test_preserve_legacy_checks_and_reject_v2_only_choices_for_a_v1_portal(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "homeview.json"
            legacy = {
                "scope": list(IDENTITY.scope), "revision": "v1-save", "enabled": True, "disable_pending": False,
                "monitors": [{"id": "ha", "kind": "ha_api", "label": "Core"},
                             {"id": "door", "kind": "battery_percent", "label": "Battery",
                              "entity": "sensor.legacy", "lowThreshold": 25}],
            }
            file.write_text(json.dumps(legacy))
            runtime = HomeviewRuntime(file, pairing)
            stored = runtime.settings.get(IDENTITY)
            self.assertEqual([m.manifest() for m in stored.monitors], [
                {"id": "ha", "kind": "ha_api", "label": "Core"},
                {"id": "door", "kind": "battery_percent", "label": "Battery", "lowThreshold": 25},
            ])
            self.assertEqual(stored.monitors[1].manifest(2)["entityGroupId"], "door")
            self.assertIsNone(stored.activation_generation)
            self.assertEqual(json.loads(file.read_text()), legacy)
            with self.assertRaisesRegex(ValueError, "v2_required"):
                runtime.preview("admin", {"revision": "v1-save", "monitors": [
                    {"kind": "tcp_service", "label": "Camera", "ip": "192.168.1.23", "port": 443}
                ]})
            with self.assertRaisesRegex(ValueError, "no_checks"):
                runtime.preview("admin", {"revision": "v1-save", "monitors": []})

    async def test_v2_activation_retry_and_exact_manifest_report_payloads(self):
        portal = FakePortal()
        portal.value = fixture("configBeforeActivation")
        accepted = fixture("config") | {"session": None, "manifestRevision": 0}
        clock = [0]
        timestamp = fixture("reportRequest")["observedAt"]
        reporter = Reporter(lambda: clock[0], lambda: timestamp, lambda: 0)
        reporter.boot = fixture("manifestRequest")["bootId"]
        requested = fixture("manifestRequest")
        monitors = []
        by_id = {
            "door-available": ("binary_sensor.front", "contact-id", "front"),
            "door-contact": ("binary_sensor.front", "contact-id", "front"),
            "light-available": ("light.hall", "light-id", "hall"),
            "light-on-off": ("light.hall", "light-id", "hall"),
            "battery": ("sensor.battery", "battery-id", "front"),
        }
        for row in requested["monitors"]:
            fields = dict(row)
            if fields["id"] in by_id:
                entity, registry, device = by_id[fields["id"]]
                fields.update(entity=entity, registryId=registry, deviceId=device)
            else:
                fields.update(ip="192.168.1.50", port=443)
            monitors.append(fields)
        selection = type("Selection", (), {
            "revision": fixture("activationRequest")["requestId"], "enabled": True, "disable_pending": False,
            "monitors": tuple(
                replace(m, device_group=None) if m.id.startswith("light-") else m
                for m in parse_monitors(monitors, stored=True, v2=True)
            ), "activation_generation": "pair-grant-1",
        })()
        expected = fixture("reportRequest")
        collector = AsyncMock()
        collector.collect_v2.return_value = (expected["observations"], expected["entityApiStatus"])

        async def activate(body):
            if clock[0] == 0:
                raise RequestFailure()
            portal.value = accepted
            return await portal.config()
        portal.activate = AsyncMock(side_effect=activate)
        for at in (0, 2):
            clock[0] = at
            with patch("homeview.new_id", return_value=requested["requestId"]):
                await reporter.step(selection, IDENTITY, portal, collector, lambda: True, lambda: None)
        self.assertEqual(portal.activate.await_args_list[0], portal.activate.await_args_list[1])
        self.assertEqual(json.loads(portal.activate.call_args.args[0]), fixture("activationRequest"))
        self.assertEqual(json.loads(portal.manifests[0]), requested)
        self.assertEqual(json.loads(portal.reports[0]), expected)

    async def test_v2_only_selection_is_not_partially_registered_on_v1_portal(self):
        portal = FakePortal()
        reporter = Reporter(lambda: 0, jitter=lambda: 0)
        selection = type("Selection", (), {
            "revision": "new", "enabled": True, "disable_pending": False,
            "monitors": parse_monitors([CONTACT], v2=True), "activation_generation": None,
        })()
        collector = AsyncMock()
        await reporter.step(selection, IDENTITY, portal, collector, lambda: True, lambda: None)
        self.assertEqual(reporter.status, "v2_required")
        self.assertEqual(portal.manifests, [])
        collector.collect.assert_not_awaited()
        collector.collect_v2.assert_not_awaited()

    async def test_remote_pause_or_delete_disarms_queued_activation(self):
        for decision in ("paused", "deleted", "owner_confirmation_required"):
            portal = FakePortal()
            portal.value = {**fixture("configBeforeActivation"), "decision": decision, "activationGeneration": None}
            portal.activate = AsyncMock()
            reporter = Reporter(lambda: 0, jitter=lambda: 0)
            selection = type("Selection", (), {
                "revision": "approved", "enabled": True, "disable_pending": False,
                "monitors": MONITORS, "activation_generation": "old-grant",
            })()
            collector = AsyncMock()
            await reporter.step(selection, IDENTITY, portal, collector, lambda: True, lambda: None)
            self.assertEqual(reporter.status, decision)
            portal.activate.assert_not_awaited()
            collector.collect_v2.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

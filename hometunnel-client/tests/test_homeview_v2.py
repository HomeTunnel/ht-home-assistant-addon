from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from test_homeview import FakePortal, IDENTITY, MONITORS, T, pairing, state
from homeview import HomeviewRuntime, Reporter, ReviewError, parse_config
from homeview_catalog import Catalog, CatalogError, is_core_admin
from homeview_checks import Collector, RequestFailure, entity_observation, stamp
from homeview_config import Settings, contains_network_address, monitor_usage, parse_monitors


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
        self.assertNotIn(key, await catalog.inventory(("other",)))
        clock[0] = 61
        self.assertIn(key, await catalog.inventory(IDENTITY.scope))
        self.assertEqual(catalog.fetch.await_count, 3)
        clock[0] = 122
        self.assertIn(key, await catalog.inventory(IDENTITY.scope))
        self.assertEqual(catalog.fetch.await_count, 4)

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


# The portal's V1/V2 corpus, plus cross-runtime boundary cases.
REJECTED_ADDRESS_LABELS = (
    "Camera 192.168.1.50", "Router 10.0.0.1", "https://ha.example.test:8123",
    "2001:db8::1234", "Home ha.local", "Door (http://router:8123)",
    "Camera [fe80::1%en0]:8123", "IPv6 ::ffff:192.0.2.32", "Home ｈａ．ｌｏｃａｌ",
    "//router:8123", "Door //router:8123", "ｈｔｔｐ：／／router:8123", "[fe80::abcd%eth0]",
    "é192.0.2.41界", "界router.localé", "界//router:8123", "界[2001:db8::41]界", "Camera fd00::",
)
ACCEPTED_ADDRESS_LABELS = (
    "Hall light (upstairs)", "Cámara: entrada 🚪", "Camera v1.2.3", "Version 2.3",
    "Clock 12:34:56", "🚪" * 64, "Ⓗall light (upstairs)",
    "界2001:db8::41界", "é::1", "word//router:8123", "Door //\ufeffrouter",
)


class SettingsAndProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_device_suggestions_use_current_name_and_validate_each_row(self):
        with tempfile.TemporaryDirectory() as directory:
            now = [0]
            runtime = HomeviewRuntime(Path(directory) / "homeview.json", pairing, lambda: now[0])
            devices = [{"id": f"device-{index}", "name": name} for index, name in enumerate(
                ("Factory name", "printer.local", "x" * 65, "device-3", "Bearer synthetic"))]
            devices[0]["name_by_user"] = "Front sensor"
            registry = [{"id": f"registry-{index}", "device_id": device["id"], "entity_id": f"sensor.demo_{index}"}
                        for index, device in enumerate(devices)]
            states = [state(row["entity_id"], "72") for row in registry]
            runtime.catalog.fetch = AsyncMock(return_value=(devices, registry, states))
            page = await runtime.discover("", 0)
            keys = {item["hint"]: item["key"] for item in page["items"]}
            ha = {"kind": "ha_api", "label": "Core"}
            rows = [{"kind": "entity_availability", "key": keys[row["entity_id"]]} for row in registry]
            revision = runtime.view()["revision"]
            with self.assertRaises(ReviewError) as error:
                await runtime.preview("admin", {"revision": revision, "monitors": [ha, *rows]})
            self.assertEqual(error.exception.rows, dict.fromkeys(range(2, 6), "custom_label_required"))
            for index, row in enumerate(rows[1:], 1):
                row["label"] = f"Custom sensor {index}"
            draft = {"revision": revision, "monitors": [ha, *rows]}
            first = await runtime.preview("admin", draft)
            self.assertEqual([m["label"] for m in first["monitors"]],
                             ["Core", "Front sensor", *(f"Custom sensor {i}" for i in range(1, 5))])
            runtime.confirm("admin", first["preview"])
            saved = runtime.view()
            devices[0]["name_by_user"] = "Renamed sensor"
            now[0] = 61
            retained = await runtime.preview("admin", {"revision": saved["revision"], "monitors": [
                ha, *({"saved": m["id"], "kind": m["kind"], "label": m["label"]} for m in saved["monitors"][1:]),
            ]})
            self.assertEqual(retained["monitors"][1]["label"], "Front sensor")
            renamed = await runtime.preview("admin", draft | {"revision": saved["revision"]})
            self.assertEqual(renamed["monitors"][1]["label"], "Renamed sensor")
            self.assertEqual(runtime.view(), saved)
            runtime.confirm("admin", renamed["preview"])
            self.assertEqual(runtime.view()["monitors"][1]["id"], saved["monitors"][1]["id"])
            self.assertEqual(runtime.view()["monitors"][1]["label"], "Renamed sensor")

    async def test_expired_inventory_marks_only_changed_rows_and_retry_keeps_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            now = [0]
            runtime = HomeviewRuntime(Path(directory) / "homeview.json", pairing, lambda: now[0])
            runtime.catalog.fetch = AsyncMock(return_value=(DEVICES, REGISTRY, STATES))
            page = await runtime.discover("", 0)
            keys = {item["hint"]: item["key"] for item in page["items"]}
            inventory = [
                {**row, "device_id": "hall"} if row["id"] == "contact-id"
                else {**row, "id": "replacement-id"} if row["id"] == "switch-id" else row
                for row in REGISTRY
            ]
            refreshed_states = [
                {**row, "state": "unavailable"} if row["entity_id"] == "light.hall" else row
                for row in STATES
            ]
            now[0] = 61
            runtime.catalog.fetch.side_effect = [CatalogError("core_unavailable"), (DEVICES, inventory, refreshed_states)]
            revision = runtime.view()["revision"]
            rows = [{"kind": "ha_api", "label": "Core"},
                    {"kind": "entity_availability", "key": keys["binary_sensor.front"]},
                    {"kind": "entity_availability", "key": keys["light.hall"]},
                    {"kind": "entity_switch", "key": keys["light.hall"]},
                    {"kind": "entity_availability", "key": keys["switch.hall"]}]
            with self.assertRaisesRegex(CatalogError, "core_unavailable"):
                await runtime.preview("admin", {"revision": revision, "monitors": rows})
            with self.assertRaises(ReviewError) as error:
                await runtime.preview("admin", {"revision": revision, "monitors": rows})
            self.assertEqual(error.exception.rows, {1: "entity_changed", 3: "check_changed", 4: "entity_changed"})
            result = await runtime.preview("admin", {"revision": revision, "monitors": [rows[0], rows[2]]})
            self.assertEqual([m["label"] for m in result["monitors"]], ["Core", "Entry"])
            self.assertEqual(runtime.catalog.fetch.await_count, 3)

    async def test_upgrade_preserves_over_limit_settings_stops_and_resumes_after_review(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "homeview.json"
            ha = {"id": "ha", "kind": "ha_api", "label": "Core"}
            entities = [{"id": f"sensor-{i}", "kind": "entity_availability", "entity": f"sensor.item_{i}",
                         "label": f"Sensor {i}"} for i in range(6)]
            value = {**entities[0], "id": "battery", "kind": "battery_percent", "label": "Battery", "lowThreshold": 25}
            tcp = [{"id": f"tcp-{i}", "kind": "tcp_service", "label": f"Service {i}", "ip": "10.1.1.5", "port": 9000 + i}
                   for i in range(4)]
            saved = {"scope": list(IDENTITY.scope), "revision": "previous", "enabled": True, "disable_pending": False,
                     "monitors": [ha, *entities, value, *tcp]}
            file.write_text(json.dumps(saved))
            runtime = HomeviewRuntime(file, pairing)
            selection = runtime.settings.get(IDENTITY)
            self.assertEqual(monitor_usage(selection.monitors), {"devices": 6, "tcpServices": 4})
            view = runtime.view()
            self.assertEqual(view["status"], "over_limit")
            self.assertTrue(view["enabled"])
            self.assertEqual(len(view["monitors"]), 12)
            self.assertEqual(view["monitors"][1]["deviceSlot"], view["monitors"][7]["deviceSlot"])
            self.assertTrue(view["monitors"][1]["legacyDevice"])
            self.assertEqual(json.loads(file.read_text()), saved)
            portal = FakePortal()
            collector = AsyncMock()
            reporter = runtime.reporter
            await reporter.step(selection, IDENTITY, portal, collector, lambda: True, lambda: None)
            collector.collect.assert_not_awaited()
            self.assertEqual((portal.manifests, portal.reports, reporter.lease), ([], [], 0))

            runtime.apply({"enabled": False})
            disabled = runtime.settings.get(IDENTITY)
            self.assertEqual(disabled.monitors, selection.monitors)
            await reporter.step(disabled, IDENTITY, portal, collector, lambda: True,
                                lambda: runtime.settings.acknowledge_disable(IDENTITY, disabled.revision))
            self.assertFalse(json.loads(portal.manifests[-1])["enabled"])
            self.assertEqual(runtime.view()["status"], "off")

            kept = [ha, *entities[:5], value, *tcp[:3]]
            rows = [{k: v for k, v in row.items() if k != "id"} if "entity" not in row else
                    {k: v for k, v in row.items() if k not in ("id", "entity")} | {"saved": row["id"]} for row in kept]
            review = await runtime.preview("admin", {"revision": disabled.revision, "monitors": rows})
            runtime.confirm("admin", review["preview"])
            corrected = runtime.settings.get(IDENTITY)
            self.assertEqual([m.id for m in corrected.monitors], [row["id"] for row in kept])
            self.assertEqual(corrected.monitors[6].low_threshold, 25)
            collector.collect.return_value = None
            await reporter.step(corrected, IDENTITY, portal, collector, lambda: True, lambda: None)
            self.assertTrue(json.loads(portal.manifests[-1])["enabled"])
            collector.collect.assert_awaited_once()

    def test_v1_and_v2_match_portal_shared_label_corpus(self):
        for v2 in (False, True):
            for label in REJECTED_ADDRESS_LABELS + ACCEPTED_ADDRESS_LABELS:
                with self.subTest(v2=v2, label=label):
                    rejected = label in REJECTED_ADDRESS_LABELS
                    self.assertEqual(contains_network_address(label), rejected)
                    rows = [{"kind": "ha_api", "label": label}]
                    if rejected:
                        with self.assertRaisesRegex(ValueError, r"^(address_in_label|invalid_label)$"):
                            Settings.validate_labels(IDENTITY, parse_monitors(rows, v2=v2))
                    else:
                        monitors = parse_monitors(rows, v2=v2)
                        Settings.validate_labels(IDENTITY, monitors)
                        self.assertEqual(monitors[0].manifest(2 if v2 else 1)["label"], label)
            for label in ("", None, " Hall", "Hall ", "\ufeffHall", "Hall\ufeff", "Hall\u0085light",
                          "Hall\u202elight", "Hall\u2066light", "🚪" * 65):
                with self.subTest(v2=v2, label=label), self.assertRaisesRegex(ValueError, "^invalid_label$"):
                    parse_monitors([{"kind": "ha_api", "label": label}], v2=v2)
            for label in ("Hall\ufefflight", "\u200bHall"):
                with self.subTest(v2=v2, label=label):
                    self.assertEqual(parse_monitors([{"kind": "ha_api", "label": label}], v2=v2)[0].label, label)

    def test_addon_keeps_stricter_private_label_checks(self):
        entity = parse_monitors([{**CONTACT, "entity": "binary_sensor._private"}], v2=True)[0]
        for label in ("Door://", "Bearer synthetic", "abcdefghijklmnop.abcdefghijklmnop.", IDENTITY.token,
                      entity.entity, entity.registry_id, entity.device_id, "canary-supervisor-token"):
            with self.subTest(label=label), patch.dict("os.environ", SUPERVISOR_TOKEN="canary-supervisor-token"):
                with self.assertRaisesRegex(ValueError, "^invalid_label$"):
                    Settings.validate_labels(IDENTITY, (replace(entity, label=label),))
        with self.assertRaisesRegex(ValueError, "^invalid_label$"):
            parse_monitors([{"kind": "ha_api", "label": "http://router:8123"}])

    async def test_preview_and_confirmation_reject_prohibited_labels_safely(self):
        with tempfile.TemporaryDirectory() as directory, self.assertNoLogs(level="WARNING"):
            runtime = HomeviewRuntime(Path(directory) / "homeview.json", pairing)
            revision = runtime.view()["revision"]
            label = "Door //router:8123"
            body = {"revision": revision, "monitors": [{"kind": "ha_api", "label": label}]}
            with self.assertRaisesRegex(ValueError, "^address_in_label$"):
                await runtime.preview("admin", body)
            # Simulate a preview issued before the address check identified this form.
            with patch("homeview_config.contains_network_address", return_value=False):
                preview = await runtime.preview("admin", body)
            with self.assertRaisesRegex(ValueError, "^address_in_label$"):
                runtime.confirm("admin", preview["preview"])
            self.assertFalse(runtime.view()["enabled"])
            self.assertEqual(runtime.view()["revision"], revision)

    async def test_saved_prohibited_labels_preserve_selection_and_discard_pending_payloads(self):
        for config, label in (
            (FakePortal().value, "Door //router:8123"),
            (FakePortal().value, "\ufeffCore"),
            (FakePortal().value, "Core\ufeff"),
            (fixture("configBeforeActivation"), "ｈｔｔｐ：／／router:8123"),
            (fixture("configBeforeActivation"), "http://router:8123"),
        ):
            with self.subTest(version=config["schemaVersion"], label=label), tempfile.TemporaryDirectory() as directory:
                file = Path(directory) / "homeview.json"
                saved = {
                    "scope": list(IDENTITY.scope), "revision": "old", "enabled": True, "disable_pending": False,
                    "activation_generation": config.get("activationGeneration"),
                    "monitors": [
                        {"id": "ha", "kind": "ha_api", "label": label},
                        {"id": "tcp", "kind": "tcp_service", "label": "Camera port", "ip": "192.168.5.20", "port": 8123},
                    ],
                }
                file.write_text(json.dumps(saved))
                runtime = HomeviewRuntime(file, pairing)
                portal = FakePortal()
                portal.value = config
                portal.activate = AsyncMock()
                now = [0]
                reporter = runtime.reporter = Reporter(lambda: now[0], jitter=lambda: 0)
                selection = runtime.settings.get(IDENTITY)
                reporter.key = (IDENTITY, selection.revision)
                reporter.manifest_pending = ("generation", b"stale manifest")
                reporter.report_pending = (0, 1, b"stale report")
                reporter.registered = ("generation", 1, "old-session")
                reporter.lease = reporter.next_attempt = 10
                collector = AsyncMock()
                with self.assertNoLogs(level="WARNING"):
                    for at in (0, 60, 120):
                        now[0] = at
                        await reporter.step(selection, IDENTITY, portal, collector, lambda: True, lambda: None)
                        self.assertEqual(runtime.view()["status"], "review_labels")
                        self.assertEqual(reporter.lease, 0)
                        self.assertIsNone(reporter.registered)
                        self.assertIsNone(reporter.manifest_pending)
                        self.assertIsNone(reporter.report_pending)
                portal.activate.assert_not_awaited()
                self.assertEqual(portal.manifests, [])
                self.assertEqual(portal.reports, [])
                collector.collect.assert_not_awaited()
                collector.collect_v2.assert_not_awaited()
                self.assertEqual(json.loads(file.read_text()), saved)
                rows = [{key: value for key, value in row.items() if key != "id"} for row in saved["monitors"]]
                rows[0]["label"] = "Core"
                preview = await runtime.preview("admin", {"revision": selection.revision, "monitors": rows})
                runtime.confirm("admin", preview["preview"])
                corrected = runtime.settings.get(IDENTITY)
                self.assertNotEqual(corrected.revision, selection.revision)
                self.assertEqual([m.id for m in corrected.monitors], ["ha", "tcp"])
                self.assertEqual(corrected.monitors[1].target, selection.monitors[1].target)

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
            preview = await runtime.preview("admin", body)
            self.assertEqual(preview["monitors"], [{k: v for k, v in row.items() if k != "key"} for row in rows])
            with self.assertRaisesRegex(ValueError, "selection_changed"):
                runtime.confirm("someone-else", preview["preview"])
            preview = await runtime.preview("admin", body)
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
            active_preview = await runtime.preview("admin", {"revision": legacy["revision"], "monitors": rows})
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
                await runtime.preview("admin", {"revision": "v1-save", "monitors": [
                    {"kind": "tcp_service", "label": "Camera", "ip": "192.168.1.23", "port": 443}
                ]})
            with self.assertRaisesRegex(ValueError, "no_checks"):
                await runtime.preview("admin", {"revision": "v1-save", "monitors": []})

    async def test_v2_activation_400_remains_retryable_with_exact_payloads(self):
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
                raise RequestFailure(400)
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

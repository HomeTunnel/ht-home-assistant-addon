"""Homeview protocol and a collector supervised separately from the NetBird agent."""
from __future__ import annotations

import asyncio
import json
import random
import threading
import time

import httpx

from homeview_catalog import Catalog
from homeview_checks import Collector, RequestFailure, parse_time, request_json, stamp
from homeview_config import Identity, KINDS, POLICY, Settings, is_id, new_id, parse_monitors

MAX_REVISION = 2147483647
MAX_SEQUENCE = 9007199254740990


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def encode(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse_config(data):
    if (type(data.get("schemaVersion")) is not int or data["schemaVersion"] not in (1, 2)
            or type(data.get("enabled")) is not bool or data.get("policy") != POLICY
            or not integer(data.get("manifestRevision"), 0, MAX_REVISION)):
        raise RequestFailure()
    session, generation = data.get("session"), data.get("consentGeneration")
    if data["enabled"] and not is_id(generation):
        raise RequestFailure()
    if not data["enabled"] and (session is not None or generation is not None):
        raise RequestFailure()
    if session is not None and (
            not isinstance(session, dict) or not is_id(session.get("id")) or not is_id(session.get("bootId"))
            or not integer(session.get("nextSequence"), 1, MAX_SEQUENCE + 1) or data["manifestRevision"] == 0):
        raise RequestFailure()
    if data["schemaVersion"] == 2:
        decision, activation = data.get("decision"), data.get("activationGeneration")
        if (decision not in ("never_enabled", "active", "paused", "deleted", "owner_confirmation_required")
                or data["enabled"] != (decision == "active")
                or "activationGeneration" not in data
                or (activation is not None and (not is_id(activation) or decision != "never_enabled"))):
            raise RequestFailure()
    return data


class Portal:
    def __init__(self, client, identity):
        self.client = client
        self.base = f"{identity.origin}/api/devices/{identity.device}/homeview/"
        self.headers = {
            "Authorization": f"Bearer {identity.token}",
            "X-Homeview-Binding-Id": identity.binding,
            "Content-Type": "application/json",
        }

    async def request(self, method, route, *, body=None, version=2):
        return await request_json(
            self.client, method, self.base + route, {**self.headers, "X-Homeview-Version": str(version)},
            body, negotiated=True,
        )

    async def config(self):
        return parse_config(await self.request("GET", "config"))

    async def mutation(self, method, route, body):
        version = json.loads(body)["schemaVersion"]
        data = await self.request(method, route, body=body, version=version)
        if type(data.get("schemaVersion")) is not int or data["schemaVersion"] != version:
            raise RequestFailure(invalid_response=True)
        return data

    async def activate(self, body):
        return parse_config(await self.mutation("POST", "activate", body))

    async def manifest(self, body):
        return parse_config(await self.mutation("PUT", "monitors", body))

    async def report(self, body):
        data = await self.mutation("POST", "reports", body)
        if not parse_time(data.get("receivedAt")) or type(data.get("duplicate")) is not bool:
            raise RequestFailure()


class Reporter:
    def __init__(self, monotonic=time.monotonic, wall=stamp, jitter=None):
        self.clock = monotonic
        self.wall = wall
        self.jitter = jitter or (lambda: random.uniform(0, 3))
        self.boot = new_id()
        self.key = None
        self.status = "off"
        self.reset()

    def reset(self):
        self.config = None
        self.registered = None
        self.lease = 0
        self.next_config = 0
        self.next_attempt = 0
        self.next_sample = 0
        self.next_sequence = 1
        self.manifest_pending = None
        self.report_pending = None
        self.manifest_rejected = False
        self.failures = 0

    def invalidate_reporting(self):
        self.registered = self.manifest_pending = self.report_pending = None
        self.lease = 0

    def accept_config(self, config):
        if self.config and self.config["schemaVersion"] != config["schemaVersion"]:
            self.registered = self.manifest_pending = self.report_pending = None
        self.config = config
        now = self.clock()
        self.next_config = now + POLICY["reportIntervalSeconds"]
        self.lease = now + POLICY["leaseSeconds"] if config["enabled"] else 0
        session = config["session"]
        marker = (config["consentGeneration"], config["manifestRevision"], session["id"]) if session else None
        if marker != self.registered:
            self.registered = None
            self.report_pending = None
        if self.registered and session:
            self.next_sequence = max(self.next_sequence, session["nextSequence"])

    async def register(self, portal, selection, current):
        config = self.config
        generation = config["consentGeneration"]
        if not self.manifest_pending or self.manifest_pending[0] != generation:
            body = encode({
                "schemaVersion": config["schemaVersion"], "bootId": self.boot, "requestId": new_id(),
                "consentGeneration": generation, "expectedRevision": config["manifestRevision"],
                "enabled": selection.enabled,
                "monitors": [monitor.manifest(config["schemaVersion"]) for monitor in selection.monitors] if selection.enabled else [],
            })
            self.manifest_pending = generation, body
        if not current():
            return False
        try:
            answer = await portal.manifest(self.manifest_pending[1])
        except RequestFailure as error:
            if error.status != 400:
                raise
            if current():
                self.manifest_rejected = True
                self.invalidate_reporting()
                self.status = "review_settings"
            return False
        if not current():
            return False
        session = answer["session"]
        if (not answer["enabled"] or answer["consentGeneration"] != generation
                or (selection.enabled and (not session or session["bootId"] != self.boot))
                or (not selection.enabled and session is not None)):
            raise RequestFailure(409)
        self.manifest_pending = None
        self.accept_config(answer)
        if session:
            self.registered = (generation, answer["manifestRevision"], session["id"])
            self.next_sequence = session["nextSequence"]
            self.next_sample = self.clock()
        return True

    def handle_failure(self, error):
        status = error.status
        self.failures += 1
        delay = min(60, 2 ** min(self.failures, 6)) + self.jitter()
        if status in (401, 402, 403, 404, 406, 409):
            self.invalidate_reporting()
            self.config = None
            self.next_config = 0
            self.status = {401: "pairing_required", 402: "portal_off", 403: "portal_off", 404: "unsupported", 406: "unsupported", 409: "waiting_portal"}[status]
            if status in (401, 402, 403, 404, 406):
                delay = 60 + self.jitter()
        elif status == 422:
            # A rejected timestamp must not be retried as fresh evidence.
            self.report_pending = None
            self.next_sequence += 1
            self.next_config = 0
            self.status = "clock_error"
        else:
            self.status = "waiting_portal"
        self.next_attempt = self.clock() + delay

    async def step(self, selection, identity, portal, collector, current, acknowledge_disable):
        key = (identity, selection.revision if selection else None) if identity else None
        if key != self.key:
            self.reset()
            self.status = "waiting_portal" if selection and selection.enabled else "off"
            self.key = key
        if not key:
            self.status = "off"
            return
        if not current():
            return
        review = "review_settings" if self.manifest_rejected else None
        if selection and selection.enabled:
            try:
                Settings.validate_labels(identity, selection.monitors)
            except ValueError:
                review = "review_labels"
        if review:
            self.invalidate_reporting()
            self.status = review
        if self.clock() < self.next_attempt:
            return
        try:
            if self.clock() >= self.next_config or self.config is None:
                config = await portal.config()
                if not current():
                    return
                self.accept_config(config)
            if not selection or not (selection.enabled or selection.disable_pending):
                self.status = "off"
                self.failures = 0
                return
            if review:
                self.lease = 0
                self.failures = 0
                if not selection.enabled and not self.config["enabled"]:
                    acknowledge_disable()
                    self.status = "off"
                return
            version = self.config["schemaVersion"]
            activation = self.config.get("activationGeneration")
            if (version == 2 and selection.enabled and not self.config["enabled"] and activation
                    and activation == getattr(selection, "activation_generation", None) and current()):
                # The local selection revision is a persisted idempotency key.
                answer = await portal.activate(encode({
                    "schemaVersion": 2, "requestId": selection.revision, "activationGeneration": activation,
                }))
                if not current():
                    return
                self.accept_config(answer)
            if not self.config["enabled"]:
                self.manifest_pending = None
                self.status = self.config.get("decision", "portal_off") if selection.enabled else "off"
                if not selection.enabled:
                    acknowledge_disable()
                return
            if selection.enabled and version == 1 and (not any(m.kind == "ha_api" for m in selection.monitors)
                    or any(m.kind not in KINDS for m in selection.monitors)):
                self.status = "v2_required"
                return
            if not self.registered or self.next_sequence > MAX_SEQUENCE:
                self.status = "waiting_portal"
                if not await self.register(portal, selection, current):
                    return
                if not selection.enabled:
                    acknowledge_disable()
                    self.status = "off"
                    return

            def allowed():
                return self.clock() < self.lease and current()

            if not allowed():
                return
            pending = self.report_pending
            if pending and self.clock() - pending[0] >= POLICY["maxObservationAgeSeconds"] - 10:
                # The portal may have committed an unacknowledged report. Never reuse its sequence.
                self.next_sequence = max(self.next_sequence, pending[1] + 1)
                self.report_pending = pending = None
            if not pending:
                if self.clock() < self.next_sample:
                    return
                started = self.clock()
                try:
                    collect = collector.collect_v2 if version == 2 else collector.collect
                    snapshot = await asyncio.wait_for(collect(selection.monitors, allowed), max(0, self.lease - self.clock()))
                except asyncio.TimeoutError:
                    return
                if snapshot is None or not allowed():
                    return
                observations, evidence = snapshot if version == 2 else (snapshot, None)
                observed_at = self.wall()
                # Core and transport stalls must not yield misleading or invalid timestamps.
                observed_time = parse_time(observed_at)
                if any(not 0 <= (observed_time - parse_time(item["checkedAt"])).total_seconds() <= 60 for item in observations):
                    raise RequestFailure(422)
                body = encode({
                    "schemaVersion": version, "sessionId": self.registered[2],
                    "manifestRevision": self.registered[1], "sequence": self.next_sequence,
                    "observedAt": observed_at, "observations": observations,
                    **({"entityApiStatus": evidence} if evidence is not None else {}),
                })
                if len(body) > POLICY["maxBodyBytes"]:
                    raise RequestFailure(422)
                self.report_pending = pending = (started, self.next_sequence, body)
                self.next_sample = started + POLICY["reportIntervalSeconds"] + self.jitter()
            if allowed():
                await portal.report(pending[2])
                self.next_sequence = max(pending[1] + 1, self.next_sequence)
                self.report_pending = None
                self.status = "reporting"
            self.failures = 0
        except RequestFailure as error:
            if current():
                self.handle_failure(error)
                if review:
                    self.status = review


class HomeviewRuntime:
    """One cancellable worker in the ingress process; independent of tunnel status."""
    def __init__(self, path, read_state):
        self.settings = Settings(path)
        self.read_state = read_state
        self.thread = None
        self.stop_event = threading.Event()
        self.loop = None
        self.wake = None
        self.active = None
        self.lock = threading.Lock()
        self.epoch = 0
        self.blocked_scope = None
        self.reporter = Reporter()
        self.catalog = Catalog()
        self.previews = {}

    def identity(self):
        return Identity.read(self.read_state())

    def _selection(self, *, for_preview=False):
        with self.lock:
            identity = self.identity()
            if self.blocked_scope and (not identity or identity.scope != self.blocked_scope):
                self.blocked_scope = None
            if identity and identity.scope == self.blocked_scope:
                identity = None
            return identity, self.settings.get(identity, for_preview=for_preview), self.epoch

    def view(self):
        identity, selection, _ = self._selection(for_preview=True)
        status = "off"
        if selection and selection.enabled:
            status = self.reporter.status if self.reporter.key == (identity, selection.revision) else "waiting_portal"
        elif selection and selection.disable_pending:
            status = "stopping"
            if self.reporter.key == (identity, selection.revision) and self.reporter.manifest_rejected:
                status = "review_settings"
        config = self.portal_config(identity)
        return {
            "protocol": config["schemaVersion"] if config else None,
            "activationAvailable": bool(config and config.get("activationGeneration")),
            "maxMonitors": POLICY["maxMonitors"],
            "paired": identity is not None, "enabled": bool(selection and selection.enabled),
            "revision": selection.revision if selection else None,
            "status": status,
            "monitors": [
                {**m.browser(), **({"selector": self.catalog.handle(identity.scope, m.registry_id)} if m.registry_id else {})}
                for m in selection.monitors
            ] if selection else [{"kind": "ha_api", "label": "Home Assistant"}],
        }

    def portal_config(self, identity):
        reporter = self.reporter
        if identity and reporter.key and reporter.key[0] == identity and reporter.clock() < reporter.next_config:
            return reporter.config

    async def discover(self, query, offset):
        identity, _, epoch = self._selection()
        if not identity:
            raise ValueError("selection_changed")
        result = await self.catalog.page(identity.scope, query, offset)
        if epoch != self.epoch or self.identity() != identity:
            raise ValueError("selection_changed")
        return result

    def preview(self, user, body):
        identity, current, epoch = self._selection(for_preview=True)
        if not identity or not current or body.get("revision") != current.revision:
            raise ValueError("selection_changed")
        if set(body) != {"revision", "monitors"} or not isinstance(body["monitors"], list):
            raise ValueError("invalid_settings")
        if not body["monitors"]:
            raise ValueError("no_checks")
        if len(body["monitors"]) > POLICY["maxMonitors"]:
            raise ValueError("invalid_settings")
        rows = []
        saved = {m.id: m for m in current.monitors}
        for row in body["monitors"]:
            if not isinstance(row, dict) or not isinstance(row.get("kind"), str):
                raise ValueError("invalid_settings")
            kind = row["kind"]
            if kind in ("ha_api", "tcp_service"):
                rows.append(row)
                continue
            if set(row) - {"kind", "label", "key", "saved", "lowThreshold"} or ("key" in row) == ("saved" in row):
                raise ValueError("invalid_settings")
            if "key" in row:
                if not is_id(row["key"]):
                    raise ValueError("invalid_settings")
                candidate = self.catalog.lookup(identity.scope, row["key"])
                if not candidate:
                    raise ValueError("inventory_expired")
                if kind not in ("entity_availability", candidate.kind):
                    raise ValueError("invalid_settings")
                entity, registry, device = candidate.entity, candidate.registry, candidate.device
            else:
                prior = saved.get(row["saved"]) if is_id(row["saved"]) else None
                if not prior or not prior.entity or prior.kind != kind:
                    raise ValueError("invalid_settings")
                entity, registry, device = prior.entity, prior.registry_id, prior.device_id
            fields = {"kind": kind, "label": row.get("label"), "entity": entity}
            if registry:
                fields.update(registryId=registry, deviceId=device)
            if "lowThreshold" in row:
                fields["lowThreshold"] = row["lowThreshold"]
            rows.append(fields)
        monitors = parse_monitors(rows, current.monitors, v2=True)
        self.settings.validate_labels(identity, monitors)
        config = self.portal_config(identity)
        v1_compatible = any(m.kind == "ha_api" for m in monitors) and all(m.kind in KINDS for m in monitors)
        if not v1_compatible and (not config or config["schemaVersion"] != 2):
            raise ValueError("v2_required")
        deadline = time.monotonic() + 120
        token = new_id()
        activation = config.get("activationGeneration") if config else None
        with self.lock:
            if epoch != self.epoch or self.identity() != identity:
                raise ValueError("selection_changed")
            # Keep a bounded number of short-lived previews across browser tabs.
            self.previews = {key: preview for key, preview in self.previews.items() if preview[0] > time.monotonic()}
            if len(self.previews) >= 8:
                self.previews.pop(next(iter(self.previews)))
            self.previews[token] = (deadline, user, identity, current.revision, monitors, activation)
        return {"preview": token, "monitors": [
            {key: value for key, value in m.manifest().items() if key != "id"} for m in monitors
        ]}

    def confirm(self, user, token):
        with self.lock:
            identity = self.identity()
            pending = self.previews.pop(token, None)
            if (not pending or pending[0] <= time.monotonic() or pending[1] != user or pending[2] != identity
                    or identity.scope == self.blocked_scope):
                raise ValueError("selection_changed")
            _, _, _, revision, monitors, activation = pending
            self.settings.commit(identity, revision, monitors, activation)
            self.epoch += 1
            self.previews.clear()
        self.interrupt()

    def apply(self, body):
        with self.lock:
            identity = self.identity()
            if identity and identity.scope == self.blocked_scope:
                identity = None
            self.settings.apply(identity, body)
            self.previews.clear()
            self.epoch += 1
        self.interrupt()

    def clear(self):
        with self.lock:
            identity = self.identity()
            self.blocked_scope = identity.scope if identity else None
            self.previews.clear()
            self.epoch += 1
            try:
                self.settings.clear()
            finally:
                self.interrupt()

    def interrupt(self):
        def cancel_active():
            if self.active:
                self.active.cancel()
            if self.wake:
                self.wake.set()
        if self.loop:
            try:
                self.loop.call_soon_threadsafe(cancel_active)
            except RuntimeError:
                pass

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="homeview-collector", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.interrupt()

    def _run(self):
        while not self.stop_event.is_set():
            try:
                asyncio.run(self._loop())
            except Exception:
                self.reporter.status = "waiting_portal"
                self.stop_event.wait(5)

    async def _loop(self):
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        self.reporter = Reporter()
        try:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=3) as client:
                collector = Collector(client)
                while not self.stop_event.is_set():
                    identity, selection, epoch = self._selection()

                    def current():
                        return (not self.stop_event.is_set() and epoch == self.epoch
                                and self.identity() == identity)

                    def acknowledge():
                        if current():
                            self.settings.acknowledge_disable(identity, selection.revision)

                    self.wake.clear()
                    self.active = asyncio.create_task(self.reporter.step(
                        selection, identity, Portal(client, identity) if identity else None, collector, current, acknowledge,
                    ))
                    try:
                        await self.active
                    except asyncio.CancelledError:
                        pass
                    finally:
                        self.active = None
                    if not self.stop_event.is_set():
                        try:
                            await asyncio.wait_for(self.wake.wait(), 1)
                        except asyncio.TimeoutError:
                            pass
        finally:
            self.wake = self.loop = None

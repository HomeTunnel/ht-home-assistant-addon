"""Homeview protocol and a collector supervised separately from the NetBird agent."""
from __future__ import annotations

import asyncio
import json
import random
import threading
import time

import httpx

from homeview_checks import Collector, RequestFailure, parse_time, request_json, stamp
from homeview_config import Identity, POLICY, Settings, is_id, new_id

MAX_REVISION = 2147483647
MAX_SEQUENCE = 9007199254740990


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def encode(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse_config(data):
    if (type(data.get("schemaVersion")) is not int or data["schemaVersion"] != 1
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

    async def config(self):
        return parse_config(await request_json(self.client, "GET", self.base + "config", self.headers))

    async def manifest(self, body):
        return parse_config(await request_json(self.client, "PUT", self.base + "monitors", self.headers, body))

    async def report(self, body):
        data = await request_json(self.client, "POST", self.base + "reports", self.headers, body)
        if (type(data.get("schemaVersion")) is not int or data["schemaVersion"] != 1
                or not parse_time(data.get("receivedAt")) or type(data.get("duplicate")) is not bool):
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
        self.failures = 0

    def accept_config(self, config):
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
                "schemaVersion": 1, "bootId": self.boot, "requestId": new_id(),
                "consentGeneration": generation, "expectedRevision": config["manifestRevision"],
                "enabled": selection.enabled,
                "monitors": [monitor.manifest() for monitor in selection.monitors] if selection.enabled else [],
            })
            self.manifest_pending = generation, body
        if not current():
            return False
        answer = await portal.manifest(self.manifest_pending[1])
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
        if status in (401, 403, 404, 409):
            self.lease = 0
            self.config = None
            self.registered = None
            self.manifest_pending = None
            self.report_pending = None
            self.next_config = 0
            self.status = {401: "pairing_required", 403: "portal_off", 404: "unsupported", 409: "waiting_portal"}[status]
            if status in (401, 403, 404):
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
        key = (identity, selection.revision) if identity and selection else None
        if key != self.key:
            self.key = key
            self.reset()
        if not key or (not selection.enabled and not selection.disable_pending):
            self.status = "off"
            return
        if not current() or self.clock() < self.next_attempt:
            return
        try:
            if self.clock() >= self.next_config or self.config is None:
                config = await portal.config()
                if not current():
                    return
                self.accept_config(config)
            if not self.config["enabled"]:
                self.manifest_pending = None
                self.status = "portal_off" if selection.enabled else "off"
                if not selection.enabled:
                    acknowledge_disable()
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
                    observations = await asyncio.wait_for(
                        collector.collect(selection.monitors, allowed), max(0, self.lease - self.clock()),
                    )
                except asyncio.TimeoutError:
                    return
                if observations is None or not allowed():
                    return
                observed_at = self.wall()
                # Do not send a report assembled across a backward wall-clock change.
                if any(item["checkedAt"] > observed_at for item in observations):
                    raise RequestFailure(422)
                body = encode({
                    "schemaVersion": 1, "sessionId": self.registered[2],
                    "manifestRevision": self.registered[1], "sequence": self.next_sequence,
                    "observedAt": observed_at, "observations": observations,
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
            self.handle_failure(error)


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
            status = self.reporter.status
        elif selection and selection.disable_pending:
            status = "stopping"
        return {
            "paired": identity is not None, "enabled": bool(selection and selection.enabled),
            "revision": selection.revision if selection else None,
            "status": status,
            "monitors": [m.local() for m in selection.monitors] if selection else [{"kind": "ha_api", "label": "Home Assistant"}],
        }

    def apply(self, body):
        with self.lock:
            identity = self.identity()
            if identity and identity.scope == self.blocked_scope:
                identity = None
            self.settings.apply(identity, body)
            self.epoch += 1
        self.interrupt()

    def clear(self):
        with self.lock:
            identity = self.identity()
            self.blocked_scope = identity.scope if identity else None
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

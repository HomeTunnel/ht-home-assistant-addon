"""Local Homeview selections, scoped to the paired device and home."""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import unicodedata
from urllib.parse import urlsplit
from uuid import uuid4

ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
ENTITY = re.compile(r"[a-z0-9_]{1,64}\.[a-z0-9_]{1,190}")
KINDS = {"ha_api", "entity_availability", "entity_connectivity", "battery_percent", "battery_binary", "tcp_service"}
V2_KINDS = {"entity_contact", "entity_light", "entity_switch"}
CONTACT_CLASSES = {"door", "window", "opening", "garage_door"}
PRIVATE = tuple(ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
POLICY = {
    "leaseSeconds": 180, "reportIntervalSeconds": 60, "staleAfterSeconds": 180,
    "maxMonitors": 50, "maxBodyBytes": 65536, "maxObservationAgeSeconds": 120, "maxFutureSkewSeconds": 30,
}


def new_id() -> str:
    return str(uuid4())


def is_id(value) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def contains_network_address(label):
    label = unicodedata.normalize("NFKC", label)
    if re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", label):
        return True
    if re.search(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*\b", label, re.IGNORECASE):
        return True
    for candidate in re.findall(r"[0-9a-f:.]*:[0-9a-f:.]+|[0-9a-f:.]*::", label, re.IGNORECASE):
        try:
            ipaddress.IPv6Address(candidate.rstrip("."))
        except ValueError:
            continue
        return True
    return False


def lan_ip(value):
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.IPv4Address(value)
        return addr if any(addr in net for net in PRIVATE) else None
    except ValueError:
        return None


def portal_origin(raw):
    """A paired origin only, with no redirects, credentials, paths or IP literals."""
    if not isinstance(raw, str) or re.search(r"[\s\\\x00-\x1f\x7f]", raw):
        return None
    try:
        url = urlsplit(raw)
        host = url.hostname
        if (url.scheme != "https" or not host or not re.fullmatch(r"[a-z0-9.-]+", host)
                or "." not in host or host.endswith(".") or ".." in host
                or url.username is not None or url.password is not None
                or url.query or url.fragment or url.path not in ("", "/")
                or url.port not in (None, 443)):
            return None
        if not re.search(r"[a-z]", host.rsplit(".", 1)[-1]):
            return None
        return f"https://{host}"
    except ValueError:
        return None


@dataclass(frozen=True)
class Identity:
    origin: str
    home: str
    device: str
    binding: str
    token: str = field(repr=False)

    @property
    def scope(self):
        return (self.origin, self.home, self.device, self.binding)

    @classmethod
    def read(cls, state):
        origin = portal_origin(state.get("portal_base_url"))
        home, device, token = (state.get(key) for key in ("home_id", "device_id", "device_token"))
        binding = state.get("binding")
        if not isinstance(binding, dict):
            return None
        binding_id = binding.get("binding_id") or binding.get("device_binding_id")
        if (not origin or not all(is_id(value) for value in (home, device, binding_id))
                or not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,512}", token)):
            return None
        if any(binding.get(key) not in (None, value) for key, value in (("home_id", home), ("device_id", device))):
            return None
        return cls(origin, home, device, binding_id, token)


@dataclass(frozen=True)
class Monitor:
    id: str
    kind: str
    label: str
    entity: str | None = field(default=None, repr=False)
    ip: str | None = field(default=None, repr=False)
    port: int | None = field(default=None, repr=False)
    low_threshold: int | None = None
    registry_id: str | None = field(default=None, repr=False)
    device_id: str | None = field(default=None, repr=False)
    entity_group: str | None = None
    device_group: str | None = None

    @property
    def target(self):
        return (self.kind, self.registry_id or self.entity, self.ip, self.port)

    def manifest(self, version=1):
        fields = {"id": self.id, "kind": self.kind, "label": self.label}
        if self.low_threshold is not None:
            fields["lowThreshold"] = self.low_threshold
        if version == 2 and self.entity is not None:
            fields["entityGroupId"] = self.entity_group
            if self.device_group is not None:
                fields["deviceGroupId"] = self.device_group
        return fields

    def browser(self):
        fields = self.manifest()
        if self.entity_group:
            fields["entityGroupId"] = self.entity_group
        if self.ip is not None:
            fields.update(ip=self.ip, port=self.port)
        return fields

    def local(self, version=1):
        fields = self.manifest(version)
        if self.entity is not None:
            fields["entity"] = self.entity
            if self.registry_id is not None:
                fields.update(registryId=self.registry_id, deviceId=self.device_id)
        if self.ip is not None:
            fields.update(ip=self.ip, port=self.port)
        return fields


def parse_monitors(value, previous=(), *, stored=False, v2=False):
    if not isinstance(value, list) or not 1 <= len(value) <= POLICY["maxMonitors"]:
        raise ValueError("invalid_monitors")
    known = {item.target: item for item in previous}
    entity_groups = {m.registry_id: m.entity_group for m in previous if m.registry_id}
    device_groups = {m.device_id: m.device_group for m in previous if m.device_id}
    monitors = []
    for row in value:
        if not isinstance(row, dict):
            raise ValueError("invalid_monitor")
        fields = dict(row)
        monitor_id = fields.pop("id", None) if stored else None
        kind, label = fields.pop("kind", None), fields.pop("label", None)
        if not isinstance(kind, str) or kind not in (KINDS | V2_KINDS if v2 else KINDS):
            raise ValueError("invalid_kind")
        if (not isinstance(label, str) or not 1 <= len(label) <= 64 or label.strip() != label
                or any(unicodedata.category(c) == "Cc" or "\u202a" <= c <= "\u202e" or "\u2066" <= c <= "\u2069" for c in label)):
            raise ValueError("invalid_label")
        # Labels are the only free text transmitted. Catch common pasted secrets/URLs.
        if re.search(r"://|(?i:\bbearer\s)|[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.", label):
            raise ValueError("invalid_label")
        label.encode("utf-8", errors="strict")
        entity = ip = port = low = registry = device = group = device_group = None
        if kind == "tcp_service":
            ip, port = fields.pop("ip", None), fields.pop("port", None)
            if lan_ip(ip) is None or type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("invalid_lan_target")
        elif kind != "ha_api":
            entity = fields.pop("entity", None)
            if not isinstance(entity, str) or not ENTITY.fullmatch(entity):
                raise ValueError("invalid_entity")
            domain = entity.split(".", 1)[0]
            if ((kind == "battery_percent" and domain != "sensor")
                    or (kind in ("battery_binary", "entity_connectivity") and domain != "binary_sensor")):
                raise ValueError("invalid_entity")
            if v2:
                registry, device = fields.pop("registryId", None), fields.pop("deviceId", None)
                if (registry is not None or device is not None) and not (is_id(registry) and is_id(device)):
                    raise ValueError("invalid_entity")
                if kind in V2_KINDS and (not registry or domain != {
                    "entity_contact": "binary_sensor", "entity_light": "light", "entity_switch": "switch",
                }[kind]):
                    raise ValueError("invalid_entity")
            if stored:
                group = fields.pop("entityGroupId", None)
                device_group = fields.pop("deviceGroupId", None)
                if (group is not None and not is_id(group)) or (device_group is not None and not is_id(device_group)):
                    raise ValueError("invalid_monitor")
            if kind == "battery_percent" and "lowThreshold" in fields:
                low = fields.pop("lowThreshold")
                if type(low) is not int or not 0 <= low <= 95:
                    raise ValueError("invalid_threshold")
        if fields or (stored and not is_id(monitor_id)):
            raise ValueError("invalid_monitor")
        old = known.get((kind, registry or entity, ip, port))
        identifier = monitor_id or (old.id if old and old.device_id == device else new_id())
        if registry:
            group = entity_groups.setdefault(registry, group or new_id())
            device_group = device_groups.setdefault(device, device_group or new_id())
        elif entity:
            # Legacy monitors have no proven registry identity. Reuse the previously
            # generated opaque monitor ID as their group on a V2 wire session.
            group = group or identifier
        monitors.append(Monitor(identifier, kind, label, entity, ip, port, low, registry, device, group, device_group))
    ha_count = sum(m.kind == "ha_api" for m in monitors)
    if (ha_count > 1 or (not v2 and ha_count != 1) or len({m.target for m in monitors}) != len(monitors)
            or len({m.id for m in monitors}) != len(monitors)
            or len({(m.kind, m.entity, m.ip, m.port) for m in monitors}) != len(monitors)):
        raise ValueError("duplicate_or_missing_monitor")
    for group in {m.entity_group for m in monitors if m.entity_group}:
        kinds = [m.kind for m in monitors if m.entity_group == group]
        if kinds.count("entity_availability") > 1 or sum(k != "entity_availability" for k in kinds) > 1:
            raise ValueError("duplicate_or_missing_monitor")
    return tuple(monitors)


@dataclass(frozen=True)
class Selection:
    scope: tuple[str, ...]
    revision: str
    enabled: bool
    disable_pending: bool
    monitors: tuple[Monitor, ...]
    activation_generation: str | None = None



class Settings:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def _read(self, identity):
        try:
            with self.path.open("rb") as handle:
                raw = handle.read(65537)
            saved = json.loads(raw) if len(raw) <= 65536 else {}
            if identity is not None and saved["scope"] == list(identity.scope):
                if not is_id(saved["revision"]) or type(saved["enabled"]) is not bool or type(saved["disable_pending"]) is not bool:
                    raise ValueError()
                activation = saved.get("activation_generation")
                if activation is not None and not is_id(activation):
                    raise ValueError()
                return Selection(identity.scope, saved["revision"], saved["enabled"], saved["disable_pending"],
                                 parse_monitors(saved["monitors"], stored=True, v2=True), activation)
        except FileNotFoundError:
            return None
        except (ValueError, KeyError, TypeError, RecursionError):
            pass
        self.path.unlink(missing_ok=True)
        return None

    def get(self, identity, *, for_preview=False):
        with self.lock:
            current = self._read(identity)
            if for_preview and identity is not None and current is None:
                # Even the first, still-disabled form belongs to a specific pairing.
                monitors = (Monitor(new_id(), "ha_api", "Home Assistant"),)
                current = Selection(identity.scope, new_id(), False, False, monitors)
                self._write(current)
            return current

    def _write(self, selection):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        v2 = (not any(m.kind == "ha_api" for m in selection.monitors) or
              any(m.registry_id or m.kind in V2_KINDS for m in selection.monitors))
        fd, temp = tempfile.mkstemp(prefix=".homeview-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({
                    "scope": list(selection.scope), "revision": selection.revision,
                    "enabled": selection.enabled, "disable_pending": selection.disable_pending,
                    "monitors": [item.local(2 if v2 else 1) for item in selection.monitors],
                    "activation_generation": selection.activation_generation,
                }, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
        finally:
            Path(temp).unlink(missing_ok=True)

    def apply(self, identity, body):
        with self.lock:
            current = self._read(identity)
            if not isinstance(body, dict):
                raise ValueError("invalid_settings")
            enabled = body.get("enabled")
            if enabled is False and set(body) == {"enabled"}:
                if current and current.enabled:
                    current = Selection(current.scope, new_id(), False, True, current.monitors)
                    self._write(current)
                return current
            if enabled is not True or set(body) != {"enabled", "monitors", "revision"}:
                raise ValueError("invalid_settings")
            if current is None or body["revision"] != current.revision:
                raise ValueError("selection_changed")
            monitors = parse_monitors(body["monitors"], current.monitors)
            self.validate_labels(identity, monitors)
            return self._commit(current, monitors, None)

    @staticmethod
    def validate_labels(identity, monitors):
        private = {identity.token, *(m.entity for m in monitors if m.entity), *(m.ip for m in monitors if m.ip),
                   *(m.registry_id for m in monitors if m.registry_id), *(m.device_id for m in monitors if m.device_id)}
        supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
        if supervisor_token:
            private.add(supervisor_token)
        if any(secret in m.label for secret in private for m in monitors):
            raise ValueError("invalid_label")
        if any(contains_network_address(m.label) for m in monitors):
            raise ValueError("address_in_label")

    def _commit(self, current, monitors, activation):
        if current.enabled and current.monitors == monitors and current.activation_generation == activation:
            return current
        selected = Selection(current.scope, new_id(), True, False, monitors, activation)
        self._write(selected)
        return selected

    def commit(self, identity, revision, monitors, activation):
        with self.lock:
            current = self._read(identity)
            if current is None or current.revision != revision:
                raise ValueError("selection_changed")
            self.validate_labels(identity, monitors)
            return self._commit(current, monitors, activation)

    def acknowledge_disable(self, identity, revision):
        with self.lock:
            current = self._read(identity)
            if current and not current.enabled and current.revision == revision and current.disable_pending:
                self._write(Selection(current.scope, revision, False, False, current.monitors))

    def clear(self):
        with self.lock:
            self.path.unlink(missing_ok=True)

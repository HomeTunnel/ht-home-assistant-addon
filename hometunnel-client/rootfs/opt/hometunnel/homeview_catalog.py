"""Read-only Home Assistant inventory through the local Supervisor proxy."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import secrets
import time
import unicodedata

from homeview_config import CONTACT_CLASSES, ENTITY, is_id

CORE_SOCKET = "ws://supervisor/core/websocket"
ENTITY_REGISTRY = "config/entity_registry/list"
DEVICE_REGISTRY = "config/device_registry/list"
CORE_STATES = "get_states"
CORE_USERS = "config/auth/list"
COMMANDS = {ENTITY_REGISTRY, DEVICE_REGISTRY, CORE_STATES, CORE_USERS}
MAX_MESSAGE = 8 * 1024 * 1024
MAX_ENTRIES = 12000
CATALOG_TTL = 60
PAGE_SIZE = 40
CORE_TIMEOUT = 6


class CatalogError(Exception):
    pass


async def core_lists(commands, token=None):
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed, InvalidStatus, WebSocketException

    class LocalConnection(connect):
        def process_redirect(self, exc):
            return exc

    if any(command not in COMMANDS for command in commands):
        raise ValueError("unexpected_core_command")
    token = token or os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        raise CatalogError("permission_denied")
    try:
        async with asyncio.timeout(CORE_TIMEOUT):
            async with LocalConnection(CORE_SOCKET, proxy=None, compression=None, open_timeout=3,
                                       close_timeout=1, max_size=MAX_MESSAGE, max_queue=1) as connection:
                hello = json.loads(await connection.recv())
                if not isinstance(hello, dict) or hello.get("type") != "auth_required":
                    raise CatalogError("core_unavailable")
                await connection.send(json.dumps({"type": "auth", "access_token": token}))
                auth = json.loads(await connection.recv())
                if not isinstance(auth, dict) or auth.get("type") != "auth_ok":
                    raise CatalogError("permission_denied")

                results = []
                for index, command in enumerate(commands, 1):
                    await connection.send(json.dumps({"id": index, "type": command}))
                    response = json.loads(await connection.recv())
                    if not isinstance(response, dict) or response.get("id") != index or response.get("type") != "result":
                        raise CatalogError("core_unavailable")
                    if response.get("success") is not True:
                        error = response.get("error")
                        code = error.get("code") if isinstance(error, dict) else None
                        raise CatalogError("permission_denied" if code in ("unauthorized", "forbidden") else "core_unavailable")
                    result = response.get("result")
                    if not isinstance(result, list):
                        raise CatalogError("core_unavailable")
                    if len(result) > MAX_ENTRIES:
                        raise CatalogError("inventory_too_large")
                    results.append(result)
                return results
    except InvalidStatus as exc:
        raise CatalogError("permission_denied" if exc.response.status_code in (401, 403) else "core_unavailable") from None
    except ConnectionClosed as exc:
        codes = {frame.code for frame in (exc.rcvd, exc.sent) if frame is not None}
        raise CatalogError("inventory_too_large" if 1009 in codes else "core_unavailable") from None
    except (OSError, TimeoutError, ValueError, RecursionError, WebSocketException):
        raise CatalogError("core_unavailable") from None


def entity_kind(entity, attributes):
    if not isinstance(attributes, dict):
        attributes = {}
    domain = entity.split(".", 1)[0]
    cls = attributes.get("device_class")
    if domain == "binary_sensor":
        if isinstance(cls, str) and cls in CONTACT_CLASSES:
            return "entity_contact"
        return {"connectivity": "entity_connectivity", "battery": "battery_binary"}.get(cls) if isinstance(cls, str) else None
    if domain == "sensor" and cls == "battery" and attributes.get("unit_of_measurement") == "%":
        return "battery_percent"
    return {"light": "entity_light", "switch": "entity_switch"}.get(domain)


def registry_entries(entries):
    """Retain only unambiguous enabled identities; raw metadata never leaves this module."""
    by_id = {}
    by_entity = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        registry, device, entity = (entry.get(k) for k in ("id", "device_id", "entity_id"))
        if not (is_id(registry) and is_id(device) and isinstance(entity, str) and ENTITY.fullmatch(entity)):
            continue
        if entry.get("disabled_by") is not None:
            continue
        by_id[registry] = (device, entity) if registry not in by_id else None
        by_entity[entity] = by_entity.get(entity, 0) + 1
    return {key: value for key, value in by_id.items() if value and by_entity[value[1]] == 1}


async def resolve_registry(token):
    (entries,) = await core_lists((ENTITY_REGISTRY,), token)
    return registry_entries(entries)


async def is_core_admin(user_id):
    (users,) = await core_lists((CORE_USERS,))
    matching = [user for user in users if isinstance(user, dict) and user.get("id") == user_id]
    if len(matching) != 1:
        return False
    user = matching[0]
    groups = user.get("group_ids")
    return user.get("is_active") is True and user.get("system_generated") is False and (
        user.get("is_owner") is True or isinstance(groups, list) and "system-admin" in groups
    )


def clean_name(value, fallback):
    if not isinstance(value, str):
        return fallback
    name = "".join(c for c in value[:128] if unicodedata.category(c) not in ("Cc", "Cf", "Cs")).strip()
    return name or fallback


@dataclass(frozen=True)
class Candidate:
    entity: str
    registry: str
    device: str
    name: str
    device_name: str
    kind: str | None


class Catalog:
    def __init__(self, fetch=core_lists, clock=time.monotonic):
        self.fetch = fetch
        self.clock = clock
        self.lock = asyncio.Lock()
        self.secret = secrets.token_bytes(32)
        self.items = {}
        self.scope = None
        self.expires = 0

    def handle(self, scope, registry):
        return hmac.new(self.secret, json.dumps((scope, registry)).encode(), hashlib.sha256).hexdigest()

    async def page(self, scope, search, offset):
        async with self.lock:
            if scope != self.scope or self.clock() >= self.expires:
                devices, registry, states = await self.fetch((DEVICE_REGISTRY, ENTITY_REGISTRY, CORE_STATES))
                self.items = self.build(scope, devices, registry, states)
                self.scope, self.expires = scope, self.clock() + CATALOG_TTL
            matches = [(key, item) for key, item in self.items.items()
                       if search in f"{item.device_name} {item.name} {item.entity}".casefold()]
            rows = []
            for key, item in matches[offset:offset + PAGE_SIZE]:
                rows.append({"key": key, "name": item.name, "device": item.device_name,
                             "group": self.handle(scope, item.device), "hint": item.entity, "kind": item.kind})
            next_offset = offset + PAGE_SIZE
            return {"items": rows, "next": next_offset if len(matches) > next_offset else None}

    def lookup(self, scope, key):
        if scope != self.scope or self.clock() >= self.expires:
            return None
        return self.items.get(key)

    def build(self, scope, devices, registry, states):
        device_names = {}
        for row in devices:
            if isinstance(row, dict) and is_id(row.get("id")) and row.get("entry_type") != "service" and row.get("disabled_by") is None:
                device_names[row["id"]] = clean_name(row.get("name_by_user") or row.get("name"), "Unnamed device")
        states_by_id = {}
        for row in states:
            if isinstance(row, dict) and isinstance(row.get("entity_id"), str):
                entity = row["entity_id"]
                states_by_id[entity] = row if entity not in states_by_id else None
        items = []
        for registry_id, (device, entity) in registry_entries(registry).items():
            state = states_by_id.get(entity)
            if device not in device_names or not state:
                continue
            value = state.get("state")
            if not isinstance(value, str) or not value.strip() or value in ("unknown", "unavailable"):
                continue
            attributes = state.get("attributes")
            attributes = attributes if isinstance(attributes, dict) else {}
            name = clean_name(attributes.get("friendly_name"), entity.split(".", 1)[1].replace("_", " ").capitalize())
            items.append(Candidate(entity, registry_id, device, name, device_names[device], entity_kind(entity, attributes)))
        items.sort(key=lambda item: (item.device_name.casefold(), item.device, item.name.casefold(), item.entity))
        return {self.handle(scope, item.registry): item for item in items}

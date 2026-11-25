"""Bounded, read-only Homeview measurements. Raw responses stay in memory."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
import socket

from homeview_catalog import CatalogError, entity_kind, resolve_registry
from homeview_config import lan_ip, POLICY

SUPERVISOR = "http://supervisor"
CHECK_TIMEOUT = 3
MAX_RESPONSE = 65536
CONCURRENCY = 4
# The standard HAOS add-on bridge uses eth0. A different or overlay route
# fails closed; never widen the add-on's declared privileges to make it work.
HAOS_BRIDGE_INTERFACE = "eth0"


class RequestFailure(Exception):
    def __init__(self, status=None, *, invalid_response=False):
        super().__init__("homeview_request_failed")
        self.status = status
        self.invalid_response = invalid_response


def stamp(value=None):
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


async def request_json(client, method, url, headers, content=None, *, negotiated=False):
    async def read():
        async with client.stream(method, url, headers={**headers, "Accept": "application/json", "Accept-Encoding": "identity"},
                                 content=content, follow_redirects=False) as response:
            if response.status_code != 200:
                raise RequestFailure(response.status_code)
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise RequestFailure(invalid_response=True)
            data = bytearray()
            async for chunk in response.aiter_raw(chunk_size=8192):
                if len(data) + len(chunk) > MAX_RESPONSE:
                    raise RequestFailure(invalid_response=True)
                data.extend(chunk)
            try:
                parsed = json.loads(data)
            except (ValueError, RecursionError):
                raise RequestFailure(invalid_response=True) from None
            if not isinstance(parsed, dict):
                raise RequestFailure(invalid_response=True)
            if negotiated:
                header = response.headers.get("X-Homeview-Version")
                if header != str(parsed.get("schemaVersion")) and not (header is None and parsed.get("schemaVersion") == 1):
                    raise RequestFailure(invalid_response=True)
            return parsed
    try:
        return await asyncio.wait_for(read(), CHECK_TIMEOUT)
    except RequestFailure:
        raise
    except Exception:
        # Exception bodies, URL paths and headers can contain credentials or entity IDs.
        raise RequestFailure() from None


def observation(monitor, result, reason=None, now=None):
    source = {"ha_api": "supervisor_core_api", "tcp_service": "local_tcp"}.get(monitor.kind, "home_assistant_entity")
    data = {"monitorId": monitor.id, "source": source, "result": result, "checkedAt": stamp(now)}
    if reason:
        data["reason"] = reason
    return data


def entity_observation(monitor, data, now=None):
    now = now or datetime.now(timezone.utc)
    state, attributes = data.get("state"), data.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    cls = attributes.get("device_class")
    if data.get("entity_id") != monitor.entity or not isinstance(state, str) or not state:
        return observation(monitor, "configuration_error", "invalid_entity", now)
    if state == "unknown" or (state == "unavailable" and monitor.kind != "entity_availability"):
        result = observation(monitor, "unknown", "no_signal", now)
    elif monitor.kind == "entity_availability":
        result = observation(monitor, "unavailable" if state == "unavailable" else "available", now=now)
    elif monitor.kind in ("entity_contact", "entity_light", "entity_switch") and state in ("on", "off") and entity_kind(monitor.entity, attributes) == monitor.kind:
        result = observation(monitor, {"on": "open", "off": "closed"}[state] if monitor.kind == "entity_contact" else state, now=now)
    elif monitor.kind == "entity_connectivity" and cls == "connectivity" and state in ("on", "off"):
        result = observation(monitor, "connected" if state == "on" else "disconnected", now=now)
    elif monitor.kind == "battery_binary" and cls == "battery" and state in ("on", "off"):
        result = observation(monitor, "low" if state == "on" else "normal", now=now)
    elif monitor.kind == "battery_percent" and cls == "battery" and attributes.get("unit_of_measurement") == "%":
        try:
            percent = float(state)
        except (ValueError, OverflowError):
            percent = math.nan
        if not math.isfinite(percent) or not 0 <= percent <= 100:
            return observation(monitor, "configuration_error", "invalid_entity", now)
        result = observation(monitor, "reading", now=now)
        result["batteryPercent"] = percent
    else:
        return observation(monitor, "configuration_error", "invalid_entity", now)
    reported = parse_time(data.get("last_reported"))
    if reported and (reported - now).total_seconds() <= POLICY["maxFutureSkewSeconds"]:
        result["sourceReportedAt"] = stamp(reported)
    return result


def lan_boundary(data):
    """Derive the same /24 cap as the portal from the live primary HAOS LAN."""
    interfaces = data.get("interfaces")
    if not isinstance(interfaces, list):
        return None
    primary = [i for i in interfaces if isinstance(i, dict) and i.get("primary") is True
               and i.get("connected") is True and i.get("enabled") is True]
    if len(primary) != 1 or primary[0].get("type") not in ("ethernet", "wireless", "vlan"):
        return None
    ipv4 = primary[0].get("ipv4")
    if not isinstance(ipv4, dict) or not isinstance(ipv4.get("address"), list):
        return None
    try:
        addresses = [ipaddress.IPv4Interface(v) for v in ipv4["address"] if isinstance(v, str)]
    except ValueError:
        return None
    private = [a for a in addresses if lan_ip(str(a.ip))]
    if len(private) != 1 or private[0].network.prefixlen >= 31:
        return None
    actual = private[0].network
    cap = ipaddress.IPv4Network(f"{private[0].ip}/24", strict=False)
    excluded = {actual.network_address, actual.broadcast_address, cap.network_address, cap.broadcast_address}
    forbidden = []
    for interface in interfaces:
        block = interface.get("ipv4") if isinstance(interface, dict) else None
        if not isinstance(block, dict):
            continue
        gateway = lan_ip(block.get("gateway"))
        if gateway:
            excluded.add(gateway)
        nameservers = block.get("nameservers")
        if isinstance(nameservers, list):
            excluded.update(addr for value in nameservers if (addr := lan_ip(value)) is not None)
        values = block.get("address")
        if isinstance(values, list):
            for value in values:
                try:
                    excluded.add(ipaddress.IPv4Interface(value).ip)
                except (ValueError, TypeError):
                    continue
    docker = data.get("docker")
    if not isinstance(docker, dict):
        return None
    try:
        forbidden.append(ipaddress.IPv4Network(docker["address"], strict=False))
        bridge_gateway = ipaddress.IPv4Address(docker["gateway"])
        if bridge_gateway not in forbidden[0]:
            return None
    except (TypeError, ValueError, KeyError):
        return None
    return actual, cap, excluded, forbidden, str(bridge_gateway)


def safe_target(ip, boundary):
    addr = lan_ip(ip)
    if addr is None or boundary is None:
        return False
    actual, cap, excluded, forbidden, _ = boundary
    return addr in actual and addr in cap and addr not in excluded and not any(addr in net for net in forbidden)


def safe_route(routes, bridge_gateway):
    return (isinstance(routes, list) and len(routes) == 1 and isinstance(routes[0], dict)
            and routes[0].get("dev") == HAOS_BRIDGE_INTERFACE
            and routes[0].get("gateway") == bridge_gateway
            and routes[0].get("type", "unicast") == "unicast"
            and not routes[0].get("multipath") and not routes[0].get("encap"))


async def tcp_probe(ip, port, bridge_gateway):
    async def connect():
        start = asyncio.get_running_loop().time()
        process = await asyncio.create_subprocess_exec("ip", "-j", "-4", "route", "get", ip,
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            output, _ = await asyncio.wait_for(process.communicate(), 1)
        finally:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
        if process.returncode:
            return "unknown", "check_failed"
        routes = json.loads(output)
        if not isinstance(routes, list) or not routes or not all(isinstance(route, dict) and route for route in routes):
            return "unknown", "check_failed"
        if not safe_route(routes, bridge_gateway):
            return "configuration_error", "unsafe_target"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Linux constant, even on Python builds that do not export the name.
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), b"eth0\0")
            sock.setblocking(False)
            try:
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), max(0, CHECK_TIMEOUT - (loop.time() - start)))
            except PermissionError:
                return "configuration_error", "permission_denied"
            except (OSError, asyncio.TimeoutError):
                return "not_responding", None
        return "responding", None

    try:
        return await connect()
    except PermissionError:
        return "configuration_error", "permission_denied"
    except (OSError, ValueError, asyncio.TimeoutError):
        return "unknown", "check_failed"


class Collector:
    def __init__(self, client, read_token=None, probe=tcp_probe, registry=resolve_registry):
        self.client = client
        self.read_token = read_token or (lambda: os.environ.get("SUPERVISOR_TOKEN"))
        self.probe = probe
        self.registry = registry

    async def collect(self, monitors, allowed):
        snapshot = await self.collect_v2(monitors, allowed)
        return snapshot[0] if snapshot is not None else None

    async def collect_v2(self, monitors, allowed):
        if not allowed():
            return None
        token = self.read_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        ha = next((m for m in monitors if m.kind == "ha_api"), None)
        api = await self.check_core(ha, headers) if ha else None
        boundary = await self.network(monitors, headers) if token and allowed() else None
        slots = asyncio.Semaphore(CONCURRENCY)
        selected = [monitor for monitor in monitors if monitor.entity is not None]
        tracked = any(m.registry_id for m in selected)
        can_read = token and (api is None or api["result"] == "responding")
        before, after = None, None
        registry_reason = "check_failed"
        if tracked and can_read and allowed():
            try:
                before = await self.registry(token)
            except CatalogError as exc:
                if str(exc) == "permission_denied":
                    registry_reason = "permission_denied"

        def path_for(monitor):
            if not monitor.registry_id:
                return monitor.entity
            pair = before.get(monitor.registry_id) if before is not None else None
            return pair[1] if pair and pair[0] == monitor.device_id else None

        async def read_entity(path):
            async with slots:
                if not allowed():
                    return None, RequestFailure(), datetime.now(timezone.utc)
                try:
                    data = await request_json(self.client, "GET", f"{SUPERVISOR}/core/api/states/{path}", headers)
                    return data, None, datetime.now(timezone.utc)
                except RequestFailure as exc:
                    return None, exc, datetime.now(timezone.utc)

        async def tcp(monitor):
            async with slots:
                if not allowed() or boundary is None:
                    return observation(monitor, "unknown", "check_failed")
                if not safe_target(monitor.ip, boundary):
                    return observation(monitor, "configuration_error", "unsafe_target")
                result, reason = await self.probe(monitor.ip, monitor.port, boundary[-1])
                return observation(monitor, result, reason)

        paths = tuple(dict.fromkeys(path for m in selected if (path := path_for(m)))) if can_read else ()
        tcp_monitors = [m for m in monitors if m.kind == "tcp_service"]
        readings, tcp_values = await asyncio.gather(
            asyncio.gather(*(read_entity(path) for path in paths)),
            asyncio.gather(*(tcp(m) for m in tcp_monitors)),
        )
        by_path = dict(zip(paths, readings))
        if tracked and before is not None and paths and allowed():
            try:
                # A concurrent replacement or rename must never expose the other entity's state.
                after = await self.registry(token)
            except CatalogError:
                pass
        evidence = any(data is not None or error.status == 404 for data, error, _ in readings)
        values = dict(zip((m.id for m in tcp_monitors), tcp_values))
        if ha:
            values[ha.id] = api
        for monitor in selected:
            path = path_for(monitor)
            if not token:
                result = observation(monitor, "configuration_error", "permission_denied")
            elif not can_read:
                result = observation(monitor, "unknown", "ha_api_unavailable")
            elif monitor.registry_id and before is None:
                result = observation(monitor, "configuration_error" if registry_reason == "permission_denied" else "unknown", registry_reason)
            elif not path:
                result = observation(monitor, "configuration_error", "entity_missing")
            elif monitor.registry_id and (after is None or after.get(monitor.registry_id) != before[monitor.registry_id]):
                result = observation(monitor, "unknown", "check_failed")
            else:
                data, error, checked = by_path[path]
                if data is not None:
                    result = entity_observation(replace(monitor, entity=path), data, checked)
                elif error.status in (401, 403, 404):
                    result = observation(monitor, "configuration_error", "entity_missing" if error.status == 404 else "permission_denied", checked)
                else:
                    outage = error.status in (None, 502, 503, 504) and not error.invalid_response
                    result = observation(monitor, "unknown", "ha_api_unavailable" if outage else "check_failed", checked)
            values[monitor.id] = result
        entity_api_status = ("responding" if evidence else "unavailable") if selected and not ha else None
        return ([values[m.id] for m in monitors], entity_api_status) if allowed() else None

    async def check_core(self, ha, headers):
        if not headers:
            return observation(ha, "configuration_error", "permission_denied")
        try:
            response = await request_json(self.client, "GET", f"{SUPERVISOR}/core/api/", headers)
            if response.get("message") == "API running.":
                return observation(ha, "responding")
        except RequestFailure as exc:
            if exc.status in (401, 403):
                return observation(ha, "configuration_error", "permission_denied")
            if not exc.invalid_response and exc.status in (None, 502, 503, 504):
                return observation(ha, "not_responding")
        return observation(ha, "unknown", "check_failed")

    async def network(self, monitors, headers):
        if not any(m.kind == "tcp_service" for m in monitors):
            return None
        try:
            result = await request_json(self.client, "GET", f"{SUPERVISOR}/network/info", headers)
        except RequestFailure:
            return None
        return lan_boundary(result["data"]) if result.get("result") == "ok" and isinstance(result.get("data"), dict) else None

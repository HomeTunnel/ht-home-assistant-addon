"""Bounded, read-only Homeview measurements. Raw responses stay in memory."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
import socket

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


async def request_json(client, method, url, headers, content=None):
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
        if process.returncode or not safe_route(json.loads(output), bridge_gateway):
            return "configuration_error", "unsafe_target"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Linux constant, even on Python builds that do not export the name.
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), b"eth0\0")
            sock.setblocking(False)
            try:
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), max(0, CHECK_TIMEOUT - (loop.time() - start)))
            except PermissionError:
                return "configuration_error", "unsafe_target"
            except (OSError, asyncio.TimeoutError):
                return "not_responding", None
        return "responding", None

    try:
        return await connect()
    except asyncio.TimeoutError:
        return "unknown", "check_failed"
    except (OSError, ValueError):
        return "configuration_error", "unsafe_target"


class Collector:
    def __init__(self, client, read_token=None, probe=tcp_probe):
        self.client = client
        self.read_token = read_token or (lambda: os.environ.get("SUPERVISOR_TOKEN"))
        self.probe = probe

    async def collect(self, monitors, allowed):
        token = self.read_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        ha = next(m for m in monitors if m.kind == "ha_api")
        if not allowed():
            return None
        if not token:
            api = observation(ha, "configuration_error", "permission_denied")
        else:
            try:
                response = await request_json(self.client, "GET", f"{SUPERVISOR}/core/api/", headers)
                api = observation(ha, "responding") if response.get("message") == "API running." else observation(ha, "unknown", "check_failed")
            except RequestFailure as exc:
                if exc.status in (401, 403):
                    api = observation(ha, "configuration_error", "permission_denied")
                elif not exc.invalid_response and exc.status in (None, 502, 503, 504):
                    api = observation(ha, "not_responding")
                else:
                    api = observation(ha, "unknown", "check_failed")

        async def network():
            if not token or not allowed() or not any(m.kind == "tcp_service" for m in monitors):
                return None
            try:
                result = await request_json(self.client, "GET", f"{SUPERVISOR}/network/info", headers)
                return lan_boundary(result["data"]) if result.get("result") == "ok" and isinstance(result.get("data"), dict) else None
            except RequestFailure:
                return None

        boundary = await network()
        slots = asyncio.Semaphore(CONCURRENCY)

        async def measure(monitor):
            if monitor.kind == "ha_api":
                return api
            async with slots:
                if not allowed():
                    return observation(monitor, "unknown", "check_failed")
                if monitor.kind == "tcp_service":
                    if not safe_target(monitor.ip, boundary):
                        return observation(monitor, "configuration_error", "unsafe_target")
                    result, reason = await self.probe(monitor.ip, monitor.port, boundary[-1])
                    return observation(monitor, result, reason)
                if api["result"] != "responding":
                    return observation(monitor, "unknown", "ha_api_unavailable")
                try:
                    response = await request_json(self.client, "GET", f"{SUPERVISOR}/core/api/states/{monitor.entity}", headers)
                    return entity_observation(monitor, response)
                except RequestFailure as exc:
                    if exc.status in (401, 403, 404):
                        return observation(monitor, "configuration_error",
                                           "entity_missing" if exc.status == 404 else "permission_denied")
                    return observation(monitor, "unknown", "check_failed")

        values = await asyncio.gather(*(measure(monitor) for monitor in monitors))
        return values if allowed() else None

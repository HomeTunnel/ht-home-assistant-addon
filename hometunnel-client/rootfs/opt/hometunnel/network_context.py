from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
from typing import Any, Dict, Iterable, Optional

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
SIOCGIFFLAGS = 0x8913
IFF_UP = 0x1
IFF_LOOPBACK = 0x8
HOMETUNNEL_HOSTNAME_SUFFIX = ".hometunnel.local"


def _unique_strings(values: Iterable[Any], normalizer) -> list[str]:
    items: list[str] = []
    for value in values:
        text = normalizer(value)
        if text and text not in items:
            items.append(text)
    return items


def normalize_dns_label(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    text = re.sub(r"[^a-z0-9-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text or None


def build_hometunnel_dns_hostname(device_id: Any, home_id: Any) -> Optional[str]:
    device_label = normalize_dns_label(device_id)
    home_label = normalize_dns_label(home_id)
    if not device_label or not home_label:
        return None
    return f"{device_label}.{home_label}{HOMETUNNEL_HOSTNAME_SUFFIX}"


def build_hometunnel_display_identity(device_id: Any, home_id: Any) -> Optional[str]:
    return build_hometunnel_dns_hostname(device_id, home_id)


def normalize_home_assistant_access_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {"direct_ip", "hometunnel_address"} else ""


def normalize_ipv4_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(ip) if ip.version == 4 else None


def normalize_ipv4_cidr(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return str(network) if network.version == 4 else None


def _parse_ip_output(output: str) -> list[Dict[str, str]]:
    entries: list[Dict[str, str]] = []
    line_re = re.compile(r"^\d+:\s+(?P<ifname>[^\s:@]+)(?:@[^\s:]+)?\s+inet\s+(?P<cidr>\d+\.\d+\.\d+\.\d+/\d+)\b")
    for line in output.splitlines():
        match = line_re.search(line.strip())
        if not match:
            continue
        cidr = normalize_ipv4_cidr(match.group("cidr"))
        if not cidr:
            continue
        ip_text = str(ipaddress.ip_interface(cidr).ip)
        entries.append(
            {
                "interface": match.group("ifname"),
                "address": ip_text,
                "cidr": cidr,
            }
        )
    return entries


def _collect_via_ip_command() -> list[Dict[str, str]]:
    ip_cmd = shutil.which("ip")
    if not ip_cmd:
        return []
    try:
        completed = subprocess.run(
            [ip_cmd, "-o", "-4", "addr", "show", "up", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except Exception:
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    return _parse_ip_output(completed.stdout)


def _interface_names() -> list[str]:
    names: list[str] = []
    try:
        for _, name in socket.if_nameindex():
            if name and name not in names:
                names.append(name)
    except Exception:
        pass
    if not names:
        try:
            for name in os.listdir("/sys/class/net"):
                if name and name not in names:
                    names.append(name)
        except Exception:
            pass
    return names


def _ioctl_text(sock: socket.socket, ifname: str, request: int) -> Optional[str]:
    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
    try:
        result = fcntl.ioctl(sock.fileno(), request, ifreq)
    except OSError:
        return None
    return socket.inet_ntoa(result[20:24])


def _ioctl_flags(sock: socket.socket, ifname: str) -> Optional[int]:
    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
    try:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
    except OSError:
        return None
    return struct.unpack("H", result[16:18])[0]


def _collect_via_ioctl() -> list[Dict[str, str]]:
    entries: list[Dict[str, str]] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception:
        return entries
    try:
        for ifname in _interface_names():
            if ifname == "lo":
                continue
            flags = _ioctl_flags(sock, ifname)
            if flags is not None and not (flags & IFF_UP):
                continue
            if flags is not None and (flags & IFF_LOOPBACK):
                continue
            address = _ioctl_text(sock, ifname, SIOCGIFADDR)
            netmask = _ioctl_text(sock, ifname, SIOCGIFNETMASK)
            cidr = None
            if address and netmask:
                try:
                    interface = ipaddress.ip_interface(f"{address}/{netmask}")
                    if interface.version == 4:
                        cidr = str(interface.network)
                        address = str(interface.ip)
                except ValueError:
                    cidr = None
            if not address or not cidr:
                continue
            entries.append({"interface": ifname, "address": address, "cidr": cidr})
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return entries


def collect_local_ipv4_context() -> Dict[str, Any]:
    entries = _collect_via_ip_command()
    source = "ip_command" if entries else "ioctl"
    if not entries:
        entries = _collect_via_ioctl()
    addresses = _unique_strings((entry.get("address") for entry in entries), normalize_ipv4_text)
    subnets = _unique_strings((entry.get("cidr") for entry in entries), normalize_ipv4_cidr)
    return {
        "source": source if entries else "unavailable",
        "local_ipv4_addresses": addresses,
        "local_ipv4_subnets": subnets,
        "local_ipv4_interfaces": [
            {
                "interface": entry.get("interface"),
                "address": entry.get("address"),
                "cidr": entry.get("cidr"),
            }
            for entry in entries
            if entry.get("interface") and entry.get("address") and entry.get("cidr")
        ],
    }


def build_network_context(
    *,
    local_ipv4_addresses: Optional[Iterable[Any]] = None,
    local_ipv4_subnets: Optional[Iterable[Any]] = None,
    target_ip: Any = None,
    target_hostname: Any = None,
    resolved_target_ip: Any = None,
    resolved_target_hostname: Any = None,
    ha_access_mode: Optional[str] = None,
    route_mode: Optional[str] = None,
    device_id: Optional[str] = None,
    home_id: Optional[str] = None,
    target_source: Optional[str] = None,
) -> Dict[str, Any]:
    local_addresses = _unique_strings(local_ipv4_addresses or [], normalize_ipv4_text)
    local_subnets = _unique_strings(local_ipv4_subnets or [], normalize_ipv4_cidr)
    selected_target_ip = normalize_ipv4_text(target_ip)
    selected_target_hostname = str(target_hostname or "").strip() or None
    routed_target_ip = normalize_ipv4_text(resolved_target_ip) or selected_target_ip
    routed_target_hostname = str(resolved_target_hostname or "").strip() or selected_target_hostname
    effective_target_ip = routed_target_ip or selected_target_ip
    effective_target_cidr = f"{effective_target_ip}/32" if effective_target_ip else None
    matching_local_subnets: list[str] = []
    exact_ip_conflict = bool(effective_target_ip and effective_target_ip in local_addresses)
    has_local_subnet_data = bool(local_subnets)
    if effective_target_ip and has_local_subnet_data:
        target_address = ipaddress.ip_address(effective_target_ip)
        for cidr in local_subnets:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if target_address in network and cidr not in matching_local_subnets:
                matching_local_subnets.append(cidr)
    subnet_overlap = bool(matching_local_subnets)
    same_lan_detected = subnet_overlap and not exact_ip_conflict
    if not effective_target_ip or (not has_local_subnet_data and not exact_ip_conflict):
        network_status = "waiting"
    elif exact_ip_conflict:
        network_status = "exact_ip_conflict"
    elif subnet_overlap:
        network_status = "same_lan" if same_lan_detected else "subnet_overlap"
    elif effective_target_ip:
        network_status = "remote"
    else:
        network_status = "waiting"
    local_bypass_recommended = same_lan_detected and not exact_ip_conflict
    if exact_ip_conflict:
        local_bypass_reason = "exact_ip_conflict"
    elif subnet_overlap:
        local_bypass_reason = "same_lan"
    elif effective_target_ip and has_local_subnet_data:
        local_bypass_reason = "remote"
    else:
        local_bypass_reason = "waiting_for_network_information"
    hometunnel_dns_hostname = build_hometunnel_dns_hostname(device_id, home_id)
    hometunnel_display_identity = build_hometunnel_display_identity(device_id, home_id)
    access_mode_value = normalize_home_assistant_access_mode(ha_access_mode) or "direct_ip"
    effective_target_hostname = hometunnel_dns_hostname if access_mode_value == "hometunnel_address" else (routed_target_hostname or effective_target_ip)
    effective_target_identity = effective_target_hostname or effective_target_ip
    return {
        "local_ipv4_addresses": local_addresses,
        "local_ipv4_subnets": local_subnets,
        "selected_target_ip": selected_target_ip,
        "selected_target_hostname": selected_target_hostname,
        "resolved_target_ip": routed_target_ip,
        "resolved_target_hostname": routed_target_hostname,
        "effective_target_ip": effective_target_ip,
        "effective_target_cidr": effective_target_cidr,
        "effective_target_hostname": effective_target_hostname,
        "matching_local_subnets": matching_local_subnets,
        "same_lan_detected": same_lan_detected,
        "exact_ip_conflict": exact_ip_conflict,
        "subnet_overlap": subnet_overlap,
        "local_bypass_recommended": local_bypass_recommended,
        "local_bypass_reason": local_bypass_reason,
        "network_status": network_status,
        "ha_access_mode": access_mode_value,
        "access_mode": access_mode_value,
        "route_mode": route_mode,
        "target_source": target_source,
        "hometunnel_dns_hostname": hometunnel_dns_hostname,
        "hometunnel_display_identity": hometunnel_display_identity,
        "overlay_identity": hometunnel_dns_hostname,
        "overlay_identity_basis": hometunnel_dns_hostname,
        "effective_target_identity": effective_target_identity,
        "identity_mode": access_mode_value,
    }

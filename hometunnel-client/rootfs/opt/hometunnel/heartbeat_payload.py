from __future__ import annotations

from typing import Any, Dict

from network_context import (
    build_hometunnel_dns_hostname,
    normalize_home_assistant_access_mode as normalize_ha_access_mode,
)


# Bounded so a large home cannot push the payload past the portal's 16KB cap.
MAX_REMOTE_PEER_REPORTS = 50


def build_remote_peer_reports(status: Dict[str, Any]) -> list[Dict[str, Any]]:
    """How each connected remote peer reaches this routing peer.

    Relayed-vs-P2P is a property of a peer *pair*, so it exists only on the two
    clients involved — never on the management API. This device's view is the
    only place the portal can learn how its clients are connected.

    Sorted by peer IP and capped: the agent skips heartbeats whose payload
    fingerprint is unchanged, so an unordered or unbounded list would churn that
    fingerprint on every peer reshuffle and defeat the dedupe.
    """
    reports: list[Dict[str, Any]] = []
    for entry in status.get("remote_peers") or []:
        if not isinstance(entry, dict):
            continue
        connection_type = entry.get("connection_type")
        peer_ip = entry.get("peer_ip")
        # Without a transport there is nothing to report, and without an IP the
        # portal cannot match the entry to a peer row.
        if connection_type not in ("p2p", "relayed") or not peer_ip:
            continue
        reports.append(
            {
                "peerIp": peer_ip,
                "peerName": entry.get("peer_name"),
                "connectionType": connection_type,
            }
        )
    reports.sort(key=lambda item: item["peerIp"])
    return reports[:MAX_REMOTE_PEER_REPORTS]


def build_heartbeat_payload(status: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    route_state = dict(state.get("route") or {})
    device_id = state.get("device_id")
    home_id = state.get("home_id")
    ha_access_mode = normalize_ha_access_mode(route_state.get("ha_access_mode")) or "direct_ip"
    binding_state = dict(state.get("binding") or {})
    binding_id = (
        binding_state.get("binding_id")
        or binding_state.get("device_binding_id")
        or state.get("binding_id")
        or state.get("device_binding_id")
    )
    binding_token = binding_state.get("signed_binding_token") or state.get("signed_binding_token")

    target_ip = route_state.get("target_ip")
    hometunnel_dns_hostname = route_state.get("hometunnel_dns_hostname") or build_hometunnel_dns_hostname(device_id, home_id)
    overlay_identity = route_state.get("overlay_identity") or hometunnel_dns_hostname
    target_hostname = (
        hometunnel_dns_hostname
        if ha_access_mode == "hometunnel_address"
        else (route_state.get("resolved_target_hostname") or route_state.get("target_hostname") or target_ip)
    )
    target_port = route_state.get("target_port") or 8123

    # The portal should treat target values as client observations, not as authoritative route assignment.
    observed_target_ip = route_state.get("resolved_target_ip") or target_ip
    observed_target_hostname = route_state.get("resolved_target_hostname") or route_state.get("target_hostname") or target_ip
    observed_target_identity = observed_target_hostname or observed_target_ip

    peer_ip = status.get("peer_ip")
    peer_name = status.get("peer_name") or state.get("peer_name")
    peer_id = state.get("netbird_peer_id")
    wireguard_public_key = status.get("wireguard_public_key")
    netbird_connected = bool(status.get("connected"))
    route_ids = route_state.get("route_ids") or []
    peer_group_ids = route_state.get("peer_group_ids") or []
    policy_ids = route_state.get("policy_ids") or []
    local_ipv4_addresses = route_state.get("local_ipv4_addresses") or []
    local_ipv4_subnets = route_state.get("local_ipv4_subnets") or []
    local_ipv4_interfaces = route_state.get("local_ipv4_interfaces") or []
    remote_peer_reports = build_remote_peer_reports(status)

    return {
        "deviceId": device_id,
        "homeId": home_id,
        **({"bindingId": binding_id} if binding_id else {}),
        **({"bindingToken": binding_token} if binding_token else {}),
        **(
            {
                "peer": {
                    "id": peer_id,
                    **({"wireguard_public_key": wireguard_public_key} if wireguard_public_key else {}),
                    "netbirdConnected": netbird_connected,
                    "peerIp": peer_ip,
                    "peerName": peer_name,
                    "isRoutingPeer": True,
                    "routingPeerCapable": bool(netbird_connected and target_ip),
                }
            }
            if peer_id
            else {}
        ),
        **({"remotePeers": remote_peer_reports} if remote_peer_reports else {}),
        "health": {
            "status": route_state.get("health_status") or "unknown",
            "routeHealthy": bool(route_state.get("healthy")),
            "localTcp8123Reachable": bool(route_state.get("local_tcp_8123_reachable")),
            "agentRunning": bool(state.get("agent_running")),
        },
        "ha": {
            "accessMode": ha_access_mode,
            "targetIp": target_ip,
            "targetHostname": target_hostname,
            "targetPort": target_port,
            "hometunnelDnsHostname": hometunnel_dns_hostname,
            "overlayIdentity": overlay_identity,
        },
        "target": {
            "currentEndpoint": route_state.get("current_endpoint"),
            "targetIp": target_ip,
            "targetHostname": route_state.get("target_hostname") or target_hostname,
            "selectedTargetIp": route_state.get("selected_target_ip"),
            "effectiveTargetCidr": route_state.get("effective_target_cidr"),
            "effectiveTargetIdentity": route_state.get("effective_target_identity"),
            "routeMode": route_state.get("route_mode"),
            "targetSource": route_state.get("target_source"),
            "targetPort": target_port,
        },
        "targetObservation": {
            "observedTargetIp": observed_target_ip,
            "observedTargetHostname": observed_target_hostname,
            "observedTargetPort": target_port,
            "observedTargetIdentity": observed_target_identity,
            "observedTargetSource": route_state.get("target_source"),
            "observedTargetCidr": route_state.get("effective_target_cidr"),
            "observedRouteMode": route_state.get("route_mode"),
            "selectedTargetIp": route_state.get("selected_target_ip"),
        },
        "route": {
            "routeNetwork": route_state.get("route_network"),
            "desiredAdvertiseRoutes": route_state.get("desired_advertise_routes"),
            "appliedAdvertiseRoutes": route_state.get("applied_advertise_routes"),
            "routeIds": route_ids,
            "peerGroupIds": peer_group_ids,
            "policyIds": policy_ids,
            "healthStatus": route_state.get("health_status") or "unknown",
            "routeHealthy": bool(route_state.get("healthy")),
            "targetReachable": bool(route_state.get("target_reachable")),
            "localTcp8123Reachable": bool(route_state.get("local_tcp_8123_reachable")),
        },
        "network": {
            "sameLanDetected": bool(route_state.get("same_lan_detected")),
            "exactIpConflict": bool(route_state.get("exact_ip_conflict")),
            "subnetOverlap": bool(route_state.get("subnet_overlap")),
            "localBypassRecommended": bool(route_state.get("local_bypass_recommended")),
            "localBypassReason": route_state.get("local_bypass_reason"),
            "networkStatus": route_state.get("network_status"),
            "localIPv4Addresses": local_ipv4_addresses,
            "localIPv4Subnets": local_ipv4_subnets,
            "localIPv4Interfaces": local_ipv4_interfaces,
            "localIPv4Source": route_state.get("local_ipv4_source"),
            "localIPv4Error": route_state.get("local_ipv4_error"),
            "matchingLocalSubnets": route_state.get("matching_local_subnets") or [],
            "effectiveTargetCidr": route_state.get("effective_target_cidr"),
            "effectiveTargetHostname": route_state.get("effective_target_hostname"),
            "effectiveTargetIdentity": route_state.get("effective_target_identity"),
            "overlayIdentity": route_state.get("overlay_identity"),
            "hometunnelDnsHostname": route_state.get("hometunnel_dns_hostname"),
            "hometunnelDisplayIdentity": route_state.get("hometunnel_display_identity"),
            "overlayIdentityBasis": route_state.get("overlay_identity_basis"),
        },
    }

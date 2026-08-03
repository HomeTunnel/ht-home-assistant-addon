from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "rootfs" / "opt" / "hometunnel"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from heartbeat_payload import MAX_REMOTE_PEER_REPORTS, build_heartbeat_payload
from network_context import build_hometunnel_dns_hostname


class HeartbeatPayloadTests(unittest.TestCase):
    def test_unresolved_authoritative_target_cannot_advertise_or_create_route(self) -> None:
        status = {
            "connected": True,
            "peer_ip": "100.64.0.10",
            "peer_name": "haos-peer",
        }
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "netbird_peer_id": "nb-management-peer-123",
            "route": {
                "ha_access_mode": "direct_ip",
                "health_status": "unresolved",
                "healthy": False,
                "target_ip": None,
                "resolved_target_ip": None,
                "target_hostname": None,
                "target_source": None,
                "route_network": None,
                "desired_advertise_routes": None,
                "effective_target_cidr": None,
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertFalse(payload["peer"]["routingPeerCapable"])
        self.assertIsNone(payload["ha"]["targetIp"])
        self.assertIsNone(payload["target"]["targetIp"])
        self.assertIsNone(payload["target"]["effectiveTargetCidr"])
        self.assertIsNone(payload["targetObservation"]["observedTargetIp"])
        self.assertIsNone(payload["targetObservation"]["observedTargetCidr"])
        self.assertIsNone(payload["route"]["routeNetwork"])
        self.assertIsNone(payload["route"]["desiredAdvertiseRoutes"])
        self.assertFalse(payload["route"]["routeHealthy"])

    def test_minimal_payload_shape_direct_ip(self) -> None:
        status = {
            "connected": True,
            "peer_id": "peer-123",
            "peer_ip": "100.64.0.10",
            "peer_name": "haos-peer",
        }
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "netbird_peer_id": "nb-management-peer-123",
            "agent_running": True,
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
                "resolved_target_hostname": "homeassistant.local",
                "current_endpoint": "http://192.168.68.141:8123",
                "target_port": 8123,
                "health_status": "healthy",
                "healthy": True,
                "local_tcp_8123_reachable": True,
                "target_reachable": True,
                "route_network": "192.168.68.141/32",
                "desired_advertise_routes": "192.168.68.141/32",
                "applied_advertise_routes": "192.168.68.141/32",
                "route_ids": ["route-1"],
                "peer_group_ids": ["group-1"],
                "policy_ids": ["policy-1"],
                "same_lan_detected": True,
                "exact_ip_conflict": False,
                "subnet_overlap": True,
                "local_bypass_recommended": True,
                "local_bypass_reason": "same_lan",
                "network_status": "same_lan",
                "local_ipv4_addresses": ["192.168.68.22"],
                "local_ipv4_subnets": ["192.168.68.0/24"],
                "local_ipv4_interfaces": [{"interface": "eth0", "address": "192.168.68.22", "cidr": "192.168.68.0/24"}],
                "local_ipv4_source": "ip_command",
                "local_ipv4_error": None,
                "matching_local_subnets": ["192.168.68.0/24"],
                "effective_target_cidr": "192.168.68.141/32",
                "effective_target_hostname": "homeassistant.local",
                "effective_target_identity": "homeassistant.local",
                "overlay_identity": "device-123.home-456.hometunnel.local",
                "hometunnel_dns_hostname": "device-123.home-456.hometunnel.local",
                "hometunnel_display_identity": "device-123.home-456.hometunnel.local",
                "overlay_identity_basis": "device-123.home-456.hometunnel.local",
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertTrue({"deviceId", "homeId", "peer", "health", "ha", "network", "route", "target"}.issubset(payload.keys()))
        self.assertEqual(set(payload["peer"].keys()), {"id", "netbirdConnected", "peerIp", "peerName", "isRoutingPeer", "routingPeerCapable"})
        self.assertEqual(set(payload["health"].keys()), {"status", "routeHealthy", "localTcp8123Reachable", "agentRunning"})
        self.assertEqual(
            set(payload["ha"].keys()),
            {"accessMode", "targetIp", "targetHostname", "targetPort", "hometunnelDnsHostname", "overlayIdentity"},
        )
        self.assertEqual(
            set(payload["network"].keys()),
            {
                "sameLanDetected",
                "exactIpConflict",
                "subnetOverlap",
                "localBypassRecommended",
                "localBypassReason",
                "networkStatus",
                "localIPv4Addresses",
                "localIPv4Subnets",
                "localIPv4Interfaces",
                "localIPv4Source",
                "localIPv4Error",
                "matchingLocalSubnets",
                "effectiveTargetCidr",
                "effectiveTargetHostname",
                "effectiveTargetIdentity",
                "overlayIdentity",
                "hometunnelDnsHostname",
                "hometunnelDisplayIdentity",
                "overlayIdentityBasis",
            },
        )
        self.assertEqual(
            set(payload["route"].keys()),
            {
                "routeNetwork",
                "desiredAdvertiseRoutes",
                "appliedAdvertiseRoutes",
                "routeIds",
                "peerGroupIds",
                "policyIds",
                "healthStatus",
                "routeHealthy",
                "targetReachable",
                "localTcp8123Reachable",
            },
        )
        self.assertEqual(
            set(payload["target"].keys()),
            {
                "currentEndpoint",
                "targetIp",
                "targetHostname",
                "selectedTargetIp",
                "effectiveTargetCidr",
                "effectiveTargetIdentity",
                "routeMode",
                "targetSource",
                "targetPort",
            },
        )
        self.assertEqual(
            set(payload["targetObservation"].keys()),
            {
                "observedTargetIp",
                "observedTargetHostname",
                "observedTargetPort",
                "observedTargetIdentity",
                "observedTargetSource",
                "observedTargetCidr",
                "observedRouteMode",
                "selectedTargetIp",
            },
        )
        self.assertEqual(payload["deviceId"], "device-123")
        self.assertEqual(payload["homeId"], "home-456")
        self.assertEqual(payload["peer"]["netbirdConnected"], True)
        self.assertEqual(payload["peer"]["isRoutingPeer"], True)
        self.assertEqual(payload["peer"]["routingPeerCapable"], True)
        self.assertEqual(payload["peer"]["id"], "nb-management-peer-123")
        self.assertEqual(payload["ha"]["accessMode"], "direct_ip")
        self.assertEqual(payload["ha"]["targetIp"], "192.168.68.141")
        self.assertEqual(payload["ha"]["targetHostname"], "homeassistant.local")
        self.assertEqual(payload["ha"]["targetPort"], 8123)
        self.assertEqual(payload["ha"]["hometunnelDnsHostname"], build_hometunnel_dns_hostname("device-123", "home-456"))
        self.assertEqual(payload["ha"]["overlayIdentity"], build_hometunnel_dns_hostname("device-123", "home-456"))
        self.assertEqual(payload["target"]["currentEndpoint"], "http://192.168.68.141:8123")
        self.assertEqual(payload["route"]["routeNetwork"], "192.168.68.141/32")
        self.assertEqual(payload["route"]["routeIds"], ["route-1"])
        self.assertEqual(payload["network"]["localIPv4Subnets"], ["192.168.68.0/24"])
        self.assertEqual(payload["network"]["localBypassReason"], "same_lan")
        self.assertEqual(payload["health"]["status"], "healthy")
        self.assertEqual(payload["health"]["routeHealthy"], True)
        self.assertEqual(payload["health"]["localTcp8123Reachable"], True)
        self.assertEqual(payload["health"]["agentRunning"], True)
        self.assertEqual(payload["network"]["sameLanDetected"], True)
        self.assertEqual(payload["network"]["exactIpConflict"], False)
        self.assertEqual(payload["network"]["subnetOverlap"], True)
        self.assertEqual(payload["network"]["localBypassRecommended"], True)
        self.assertEqual(payload["targetObservation"]["observedTargetIp"], "192.168.68.141")
        self.assertEqual(payload["targetObservation"]["observedTargetHostname"], "homeassistant.local")
        self.assertEqual(payload["targetObservation"]["observedTargetPort"], 8123)
        self.assertEqual(payload["targetObservation"]["observedTargetIdentity"], "homeassistant.local")
        self.assertEqual(payload["targetObservation"]["observedTargetSource"], None)
        self.assertEqual(payload["targetObservation"]["observedTargetCidr"], "192.168.68.141/32")
        self.assertEqual(payload["targetObservation"]["observedRouteMode"], None)
        self.assertNotIn("resolvedTargetIp", payload["target"])
        self.assertNotIn("resolvedTargetHostname", payload["target"])
        self.assertNotIn("binding", payload)
        self.assertNotIn("networkContext", payload)
        self.assertNotIn("connected", payload)
        self.assertNotIn("peerIp", payload)
        self.assertNotIn("peerName", payload)
        self.assertNotIn("peerId", payload)

    def test_missing_peer_id_omits_peer_block(self) -> None:
        status = {"connected": True, "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertNotIn("peer", payload)

    def test_remote_peers_report_transport_sorted_and_filtered(self) -> None:
        status = {
            "connected": True,
            "peer_id": "peer-123",
            "peer_ip": "100.64.0.10",
            "peer_name": "haos-peer",
            "remote_peers": [
                {"peer_ip": "100.64.0.30", "peer_name": "laptop", "connection_type": "relayed"},
                {"peer_ip": "100.64.0.20", "peer_name": "phone", "connection_type": "p2p"},
                # No transport: nothing to report, so it is left out entirely.
                {"peer_ip": "100.64.0.40", "peer_name": "tablet", "connection_type": None},
                # No IP: the portal would have nothing to match the entry against.
                {"peer_ip": None, "peer_name": "ghost", "connection_type": "p2p"},
            ],
        }
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "netbird_peer_id": "nb-management-peer-123",
            "route": {"ha_access_mode": "direct_ip", "target_ip": "192.168.68.141"},
        }

        payload = build_heartbeat_payload(status, state)

        self.assertEqual(
            payload["remotePeers"],
            [
                {"peerIp": "100.64.0.20", "peerName": "phone", "connectionType": "p2p"},
                {"peerIp": "100.64.0.30", "peerName": "laptop", "connectionType": "relayed"},
            ],
        )

    def test_remote_peers_omitted_when_no_transport_is_known(self) -> None:
        status = {
            "connected": True,
            "peer_id": "peer-123",
            "peer_ip": "100.64.0.10",
            "remote_peers": [{"peer_ip": "100.64.0.20", "connection_type": None}],
        }
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "netbird_peer_id": "nb-management-peer-123",
            "route": {"ha_access_mode": "direct_ip", "target_ip": "192.168.68.141"},
        }

        payload = build_heartbeat_payload(status, state)

        self.assertNotIn("remotePeers", payload)

    def test_remote_peers_are_capped(self) -> None:
        status = {
            "connected": True,
            "peer_id": "peer-123",
            "peer_ip": "100.64.0.1",
            "remote_peers": [
                {"peer_ip": f"100.64.1.{index}", "connection_type": "p2p"} for index in range(1, 120)
            ],
        }
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "netbird_peer_id": "nb-management-peer-123",
            "route": {"ha_access_mode": "direct_ip", "target_ip": "192.168.68.141"},
        }

        payload = build_heartbeat_payload(status, state)

        self.assertEqual(len(payload["remotePeers"]), MAX_REMOTE_PEER_REPORTS)

    def test_wireguard_public_key_is_diagnostic_only(self) -> None:
        wireguard_public_key = "u" * 44
        status = {
            "connected": True,
            "peer_id": wireguard_public_key,
            "wireguard_public_key": wireguard_public_key,
            "peer_ip": "100.64.0.10",
            "peer_name": "haos-peer",
        }
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "netbird_peer_id": "nb-management-peer-123",
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertEqual(payload["peer"]["id"], "nb-management-peer-123")
        self.assertEqual(payload["peer"]["wireguard_public_key"], wireguard_public_key)
        self.assertNotEqual(payload["peer"]["id"], wireguard_public_key)

    def test_hometunnel_address_uses_dns_hostname(self) -> None:
        status = {"connected": True, "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        state = {
            "device_id": "Device_123",
            "home_id": "Home_456",
            "route": {
                "ha_access_mode": "hometunnel_address",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
                "target_port": 8123,
            },
        }

        payload = build_heartbeat_payload(status, state)

        expected_hostname = build_hometunnel_dns_hostname("Device_123", "Home_456")
        self.assertEqual(payload["ha"]["targetHostname"], expected_hostname)
        self.assertEqual(payload["ha"]["hometunnelDnsHostname"], expected_hostname)
        self.assertEqual(payload["ha"]["overlayIdentity"], expected_hostname)

    def test_binding_assertion_is_included_when_present(self) -> None:
        status = {"connected": True, "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "binding": {
                "binding_id": "binding-123",
                "device_binding_id": "device-binding-123",
                "signed_binding_token": "signed-token-123",
            },
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertEqual(payload["bindingId"], "binding-123")
        self.assertEqual(payload["bindingToken"], "signed-token-123")
        self.assertNotIn("peer", payload)
        self.assertNotIn("binding", payload)
        self.assertNotIn("binding_id", payload)
        self.assertNotIn("binding_token", payload)

    def test_device_binding_id_is_sent_as_binding_id(self) -> None:
        status = {"connected": True, "peer_id": "peer-123", "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "binding": {
                "device_binding_id": "device-binding-123",
                "signed_binding_token": "signed-token-123",
            },
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertEqual(payload["bindingId"], "device-binding-123")
        self.assertEqual(payload["bindingToken"], "signed-token-123")

    def test_binding_token_is_optional_when_binding_id_is_present(self) -> None:
        status = {"connected": True, "peer_id": "peer-123", "peer_ip": "100.64.0.10", "peer_name": "haos-peer"}
        state = {
            "device_id": "device-123",
            "home_id": "home-456",
            "binding": {
                "binding_id": "binding-123",
            },
            "route": {
                "ha_access_mode": "direct_ip",
                "target_ip": "192.168.68.141",
                "target_hostname": "homeassistant.local",
            },
        }

        payload = build_heartbeat_payload(status, state)

        self.assertEqual(payload["bindingId"], "binding-123")
        self.assertNotIn("bindingToken", payload)


if __name__ == "__main__":
    unittest.main()

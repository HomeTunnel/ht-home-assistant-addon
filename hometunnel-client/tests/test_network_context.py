from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "rootfs" / "opt" / "hometunnel"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network_context import (
    _parse_ip_output,
    build_hometunnel_dns_hostname,
    build_network_context,
)


class NetworkContextTests(unittest.TestCase):
    def test_same_subnet_prefers_local_bypass(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["192.168.68.22"],
            local_ipv4_subnets=["192.168.68.0/24"],
            target_ip="192.168.68.141",
            target_hostname="homeassistant.local",
            ha_access_mode="direct_ip",
            device_id="device-123",
            home_id="home-456",
        )

        self.assertEqual(context["network_status"], "same_lan")
        self.assertTrue(context["same_lan_detected"])
        self.assertFalse(context["exact_ip_conflict"])
        self.assertTrue(context["subnet_overlap"])
        self.assertTrue(context["local_bypass_recommended"])
        self.assertEqual(context["effective_target_cidr"], "192.168.68.141/32")
        self.assertEqual(context["overlay_identity_basis"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["overlay_identity"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["hometunnel_dns_hostname"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["effective_target_hostname"], "homeassistant.local")
        self.assertEqual(context["effective_target_identity"], "homeassistant.local")

    def test_different_subnet_routes_securely(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["10.0.0.12"],
            local_ipv4_subnets=["10.0.0.0/24"],
            target_ip="192.168.68.141",
        )

        self.assertEqual(context["network_status"], "remote")
        self.assertFalse(context["same_lan_detected"])
        self.assertFalse(context["exact_ip_conflict"])
        self.assertFalse(context["subnet_overlap"])
        self.assertFalse(context["local_bypass_recommended"])

    def test_exact_ip_conflict_is_highest_severity(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["192.168.68.141"],
            local_ipv4_subnets=["192.168.68.0/24"],
            target_ip="192.168.68.141",
        )

        self.assertEqual(context["network_status"], "exact_ip_conflict")
        self.assertTrue(context["exact_ip_conflict"])
        self.assertTrue(context["subnet_overlap"])
        self.assertFalse(context["same_lan_detected"])
        self.assertFalse(context["local_bypass_recommended"])

    def test_two_homes_same_ip_range_stays_explicit(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["192.168.68.22"],
            local_ipv4_subnets=["192.168.68.0/24"],
            target_ip="192.168.68.141",
            ha_access_mode="direct_ip",
            route_mode="host-only",
        )

        self.assertEqual(context["network_status"], "same_lan")
        self.assertEqual(context["matching_local_subnets"], ["192.168.68.0/24"])
        self.assertTrue(context["local_bypass_recommended"])

    def test_mobile_network_switch_updates_relationship(self) -> None:
        home_context = build_network_context(
            local_ipv4_addresses=["192.168.1.25"],
            local_ipv4_subnets=["192.168.1.0/24"],
            target_ip="192.168.1.141",
        )
        away_context = build_network_context(
            local_ipv4_addresses=["172.16.5.20"],
            local_ipv4_subnets=["172.16.5.0/24"],
            target_ip="192.168.1.141",
        )

        self.assertEqual(home_context["network_status"], "same_lan")
        self.assertEqual(away_context["network_status"], "remote")
        self.assertNotEqual(home_context["network_status"], away_context["network_status"])

    def test_vpn_and_local_networks_coexist(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["10.8.0.8", "192.168.1.12"],
            local_ipv4_subnets=["10.8.0.0/24", "192.168.1.0/24"],
            target_ip="10.8.0.20",
        )

        self.assertEqual(context["network_status"], "same_lan")
        self.assertTrue(context["same_lan_detected"])
        self.assertIn("10.8.0.0/24", context["matching_local_subnets"])
        self.assertNotIn("192.168.1.0/24", context["matching_local_subnets"])

    def test_incomplete_network_info_reports_waiting(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["192.168.1.12"],
            local_ipv4_subnets=[],
            target_ip="192.168.1.141",
        )

        self.assertEqual(context["network_status"], "waiting")
        self.assertFalse(context["subnet_overlap"])
        self.assertFalse(context["local_bypass_recommended"])

    def test_hometunnel_address_uses_dns_hostname(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["10.0.0.12"],
            local_ipv4_subnets=["10.0.0.0/24"],
            target_ip="192.168.68.141",
            target_hostname="homeassistant.local",
            resolved_target_hostname="homeassistant.local",
            ha_access_mode="hometunnel_address",
            device_id="device-123",
            home_id="home-456",
        )

        self.assertEqual(context["ha_access_mode"], "hometunnel_address")
        self.assertEqual(context["overlay_identity"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["overlay_identity_basis"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["effective_target_hostname"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["effective_target_identity"], "device-123.home-456.hometunnel.local")
        self.assertEqual(context["hometunnel_display_identity"], "device-123.home-456.hometunnel.local")
        self.assertNotIn("@", context["effective_target_hostname"])
        self.assertNotIn(".io", context["effective_target_hostname"])

    def test_hometunnel_hostname_contract_uses_canonical_dns_suffix(self) -> None:
        context = build_network_context(
            device_id="Device_123",
            home_id="Home 456",
        )

        expected = "device-123.home-456.hometunnel.local"
        self.assertEqual(build_hometunnel_dns_hostname("Device_123", "Home 456"), expected)
        self.assertEqual(context["hometunnel_dns_hostname"], expected)
        self.assertEqual(context["overlay_identity"], expected)
        self.assertEqual(context["overlay_identity_basis"], expected)
        self.assertEqual(context["hometunnel_display_identity"], expected)
        self.assertTrue(context["hometunnel_dns_hostname"].endswith(".hometunnel.local"))
        self.assertEqual(context["hometunnel_dns_hostname"].count("."), 3)
        self.assertNotIn("@", context["hometunnel_dns_hostname"])
        self.assertNotIn(".io", context["hometunnel_dns_hostname"])


class ParseIpOutputTests(unittest.TestCase):
    def test_preserves_host_bits(self) -> None:
        # `ip -o -4 addr show` style output. The address must be the host's own
        # address, not the network base (regression: normalize-before-extract bug).
        output = (
            "2: eth0    inet 172.30.32.5/23 brd 172.30.33.255 scope global eth0\\n"
            "3: wt0    inet 100.87.34.152/16 scope global wt0\\n"
        ).replace("\\n", "\n")
        entries = _parse_ip_output(output)
        by_iface = {entry["interface"]: entry for entry in entries}
        self.assertEqual(by_iface["eth0"]["address"], "172.30.32.5")
        self.assertEqual(by_iface["eth0"]["cidr"], "172.30.32.0/23")
        self.assertEqual(by_iface["wt0"]["address"], "100.87.34.152")
        self.assertEqual(by_iface["wt0"]["cidr"], "100.87.0.0/16")


class SupervisorHostLanTests(unittest.TestCase):
    def test_host_lan_cidr_is_diagnostic_not_a_container_overlap(self) -> None:
        # The Supervisor-selected HAOS address is the intended target. It is not
        # an interface inside the addon container and must not be compared with
        # itself as if another local peer owned it.
        context = build_network_context(
            local_ipv4_addresses=["172.30.32.5", "100.87.34.152"],
            local_ipv4_subnets=["172.30.32.0/23", "100.87.0.0/16"],
            target_ip="192.168.68.141",
            host_lan_cidr="192.168.68.151/24",
        )
        self.assertFalse(context["same_lan_detected"])
        self.assertFalse(context["subnet_overlap"])
        self.assertFalse(context["exact_ip_conflict"])
        self.assertEqual(context["network_status"], "remote")
        self.assertEqual(context["host_lan_address"], "192.168.68.151")
        self.assertEqual(context["host_lan_subnet"], "192.168.68.0/24")
        self.assertNotIn("192.168.68.0/24", context["local_ipv4_subnets"])

    def test_own_supervisor_target_is_not_an_exact_conflict(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["172.30.32.5"],
            local_ipv4_subnets=["172.30.32.0/23"],
            target_ip="192.168.68.151",
            host_lan_cidr="192.168.68.151/24",
        )
        self.assertFalse(context["exact_ip_conflict"])
        self.assertFalse(context["subnet_overlap"])
        self.assertEqual(context["network_status"], "remote")

    def test_real_container_interface_conflict_remains_detected(self) -> None:
        context = build_network_context(
            local_ipv4_addresses=["172.30.32.5", "100.87.34.152"],
            local_ipv4_subnets=["172.30.32.0/23", "100.87.0.0/16"],
            target_ip="100.87.34.152",
            host_lan_cidr="192.168.68.151/24",
        )
        self.assertTrue(context["exact_ip_conflict"])
        self.assertEqual(context["network_status"], "exact_ip_conflict")


if __name__ == "__main__":
    unittest.main()

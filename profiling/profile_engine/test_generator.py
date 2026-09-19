"""Unit tests for statistical profile generation."""

from __future__ import annotations

import unittest
from pathlib import Path

from profiling.profile_engine.generator import CaptureModel, RuleKey, RuleStats, generate_profile


def stats(packets: int = 2) -> RuleStats:
    result = RuleStats()
    for _ in range(packets):
        result.observe(100, 1)
    return result


def model(rules: dict[RuleKey, RuleStats]) -> CaptureModel:
    return CaptureModel(
        pcap=Path("Camera_001122334455.pcap"),
        device_name="Camera",
        device_mac="00:11:22:33:44:55",
        dns_by_ip={},
        rules=rules,
        start_time=300.0,
        end_time=600.0,
        packet_count=sum(item.packets for item in rules.values()),
    )


class GeneratorTests(unittest.TestCase):
    def test_local_tcp_rule_uses_device_side_port(self) -> None:
        key = RuleKey("from-device", "ipv4", 6, "192.168.1.2", 80, "device")
        document = generate_profile(model({key: stats()}))
        ace = document["ietf-access-control-list:access-lists"]["acl"][0]["aces"]["ace"][0]
        self.assertEqual(ace["matches"]["tcp"]["source-port"]["port"], 80)

    def test_high_cardinality_ports_are_generalized(self) -> None:
        rules = {
            RuleKey("from-device", "ipv4", 17, "203.0.113.9", 20000 + index): stats()
            for index in range(12)
        }
        document = generate_profile(model(rules))
        aces = document["ietf-access-control-list:access-lists"]["acl"][0]["aces"]["ace"]
        self.assertEqual(len(aces), 1)
        self.assertNotIn("udp", aces[0]["matches"])

    def test_dhcp_broadcast_also_infers_gateway_controller(self) -> None:
        key = RuleKey("from-device", "ipv4", 17, "255.255.255.255", 67)
        document = generate_profile(model({key: stats()}))
        aces = document["ietf-access-control-list:access-lists"]["acl"][0]["aces"]["ace"]
        self.assertEqual(len(aces), 2)
        self.assertIn(
            "urn:ietf:params:mud:gateway",
            [ace["matches"].get("ietf-mud:mud", {}).get("controller") for ace in aces],
        )
        self.assertIn(
            "255.255.255.255/32",
            [ace["matches"].get("ipv4", {}).get("dst-ipv4-network") for ace in aces],
        )

    def test_adaptive_support_scales_with_capture_size(self) -> None:
        key = RuleKey("from-device", "ipv4", 6, "203.0.113.10", 443)
        document = generate_profile(model({key: stats(1000)}), min_packets=None)
        selection = document["automud:behavioral-statistics"]["filter"]
        self.assertEqual(selection["min-packets"], 10)
        self.assertEqual(selection["min-packets-mode"], "adaptive-1pct-capped-5000")


if __name__ == "__main__":
    unittest.main()

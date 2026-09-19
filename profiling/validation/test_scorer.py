"""Unit tests for MUD feature normalization and scoring."""

from __future__ import annotations

import unittest

from profiling.validation.scorer import compare_profiles, extract_features


def profile(endpoint: str = "api.example.com", port: int = 443) -> dict:
    return {
        "ietf-mud:mud": {
            "from-device-policy": {"access-lists": {"access-list": [{"name": "from-ipv4-test"}]}},
            "to-device-policy": {"access-lists": {"access-list": []}},
        },
        "ietf-access-control-list:access-lists": {
            "acl": [
                {
                    "name": "from-ipv4-test",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "rule",
                                "matches": {
                                    "ipv4": {"protocol": 6, "ietf-acldns:dst-dnsname": endpoint},
                                    "tcp": {"destination-port": {"operator": "eq", "port": port}},
                                },
                            }
                        ]
                    },
                }
            ]
        },
    }


class ScorerTests(unittest.TestCase):
    def test_identical_profiles_score_one_hundred(self) -> None:
        result = compare_profiles(profile(), profile())
        self.assertEqual(result["profile_fidelity_percent"], 100.0)
        self.assertEqual(result["overall_similarity_percent"], 100.0)

    def test_missing_endpoint_lowers_fidelity(self) -> None:
        result = compare_profiles(profile("other.example.com"), profile())
        self.assertEqual(result["profile_fidelity_percent"], 0.0)
        self.assertIn("from-device|dns:api.example.com", result["missing_reference_endpoints"])

    def test_feature_normalization_strips_dns_dot(self) -> None:
        features = extract_features(profile("API.Example.COM."))
        self.assertEqual(next(iter(features)).endpoint, "dns:api.example.com")

    def test_overlapping_ip_networks_count_as_same_endpoint(self) -> None:
        generated = profile()
        reference = profile()
        generated_match = generated["ietf-access-control-list:access-lists"]["acl"][0]["aces"]["ace"][0]["matches"]
        reference_match = reference["ietf-access-control-list:access-lists"]["acl"][0]["aces"]["ace"][0]["matches"]
        generated_match["ipv4"].pop("ietf-acldns:dst-dnsname")
        reference_match["ipv4"].pop("ietf-acldns:dst-dnsname")
        generated_match["ipv4"]["destination-ipv4-network"] = "239.1.2.3/32"
        reference_match["ipv4"]["destination-ipv4-network"] = "239.0.0.0/8"
        self.assertEqual(compare_profiles(generated, reference)["profile_fidelity_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()

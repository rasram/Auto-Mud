"""Regression tests for Zeek window deviation components."""

import unittest

from profiling.profile_engine.score_window import raw_components


class ScoreWindowTests(unittest.TestCase):
    def test_new_destination_port_is_scored(self):
        profile = {
            "endpoints": {
                "destination_ips": {},
                "domains": {},
                "tls_server_names": {},
                "destination_ports": {"tcp/80": 3},
                "listening_ports": {},
            },
            "window_features": {
                "bytes_total": None,
                "flow_count": None,
                "tcp_failed_ratio": None,
            },
            "service_distribution": {},
        }
        window = {
            "destinations": [],
            "domains": [],
            "destination_ports": ["tcp/9999"],
            "service_distribution": {},
        }

        components, evidence = raw_components(profile, window)

        self.assertEqual(components["new_ports"], 1.0)
        self.assertEqual(evidence["new_ports"], ["tcp/9999"])


if __name__ == "__main__":
    unittest.main()

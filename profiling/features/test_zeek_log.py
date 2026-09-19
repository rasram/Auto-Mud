"""Tests for device attribution of TLS certificate names."""

import tempfile
import unittest
from pathlib import Path

from profiling.features.zeek_log import read_tls_server_names


class ZeekLogTests(unittest.TestCase):
    def test_x509_names_follow_filtered_ssl_certificate_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            zeek_dir = Path(directory)
            (zeek_dir / "ssl.log").write_text(
                "#fields\tid.orig_h\tserver_name\tcert_chain_fuids\n"
                "192.0.2.1\tapi.example.com\tF1\n"
                "192.0.2.2\tother.example.net\tF2\n",
                encoding="utf-8",
            )
            (zeek_dir / "x509.log").write_text(
                "#fields\tid\tcertificate.subject\n"
                "F1\tCN=api.example.com\n"
                "F2\tCN=other.example.net\n",
                encoding="utf-8",
            )

            names = list(read_tls_server_names(zeek_dir, ips={"192.0.2.1"}))

        self.assertEqual(names, ["api.example.com", "api.example.com"])


if __name__ == "__main__":
    unittest.main()

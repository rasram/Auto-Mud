"""Regression tests for fields passed from Zeek flows to live windows."""

import tempfile
import unittest
from pathlib import Path

from profiling.features.windows import build_windows


class WindowTests(unittest.TestCase):
    def test_destination_ports_survive_flow_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            zeek_dir = Path(directory)
            (zeek_dir / "conn.log").write_text(
                "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tservice\t"
                "conn_state\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\t"
                "orig_l2_addr\tresp_l2_addr\n"
                "100.0\t192.0.2.1\t203.0.113.9\t443\ttcp\tssl\tSF\t"
                "50\t100\t1\t2\t00:11:22:33:44:55\taa:bb:cc:dd:ee:ff\n",
                encoding="utf-8",
            )

            windows = list(build_windows(zeek_dir, "00:11:22:33:44:55"))

        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]["destination_ports"], ["tcp/443"])


if __name__ == "__main__":
    unittest.main()

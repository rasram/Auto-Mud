import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from report import build_report


class ReportTests(unittest.TestCase):
    def test_missing_scores_policy_unknowns_and_response_unavailability(self):
        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root) / name for name in ("detection.json", "mud.jsonl", "response.json")]
            paths[0].write_text(json.dumps([
                {"head": "A", "label": 1, "flag": True},
                {"head": "A", "label": 1, "flag": None},
                {"head": "B", "label": 0, "flag": None},
                {"head": "B", "label": 0, "flag": False, "eligible": False},
            ]))
            paths[1].write_text('\n'.join(json.dumps(row) for row in [
                {"expected": "denied", "actual": "denied"},
                {"expected": "denied", "actual": "unknown_device"},
                {"expected": "unsupported_external_policy", "actual": "unknown_policy"},
            ]))
            paths[2].write_text(json.dumps([
                {"required": True, "proposed": True},
                {"required": True, "proposed": None},
                {"required": False, "proposed": False},
            ]))
            report = build_report(*paths)
            self.assertEqual(report["detection"]["A"]["population_recall"], .5)
            self.assertEqual(report["detection"]["B"]["TN"], 0)
            self.assertEqual(report["detection"]["B"]["excluded"], 1)
            self.assertEqual(report["mud"]["binary_coverage_of_all_records"], 1 / 3)
            self.assertEqual(report["mud"]["unavailable_forbidden"], 1)
            self.assertEqual(report["response"]["FN"], 0)
            self.assertEqual(report["response"]["unavailable"], 1)

    def test_cli_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "records.json"
            original = '[{"head":"A","label":1,"flag":true}]'
            path.write_text(original)
            result = subprocess.run([
                sys.executable, str(Path(__file__).with_name("report.py")),
                "--detection", str(path), "--output", str(path),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(), original)


if __name__ == "__main__":
    unittest.main()

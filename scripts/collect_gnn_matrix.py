"""Run the labeled scenario matrix on Mininet or render it on a virtual packet clock."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.schema import read_json, file_hash, require


def virtual_start(anchor, session_id):
    require(anchor % 86400 == 0, "Virtual matrix start must be UTC midnight")
    minute = int.from_bytes(hashlib.sha256(session_id.encode()).digest()[:8], "big") % 1440
    return anchor + minute * 60


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--virtual", action="store_true", help="Generate a synthetic PCAP on a virtual UTC clock")
    parser.add_argument("--start", type=int, default=1704067200, help="Virtual UTC midnight anchor; sessions are spread across the day")
    parser.add_argument("--zeek", default="zeek", help="Zeek executable used for offline extraction")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    matrix = args.matrix.resolve()
    entries = read_json(matrix)["runs"]
    if args.limit is not None:
        entries = entries[:args.limit]
    for i, entry in enumerate(entries, 1):
        plan_path = matrix.parent / entry["plan"]
        plan = read_json(plan_path)
        directory = args.runs_root.resolve() / plan["run_id"]
        print(f"[{i}/{len(entries)}] {plan['run_id']} ({entry['partition']})", flush=True)
        if args.dry_run:
            continue
        if (directory / "manifest.json").exists():
            m = read_json(directory / "manifest.json")
            require(m["capture_complete"] and m["plan_sha256"] == file_hash(plan_path),
                    f"Existing run {directory} is incomplete or from a different plan. Archive it before retrying.")
            require(m.get("pcap_sha256") == file_hash(directory / "capture.pcap"), "Existing capture changed")
            require((m["source"] == "virtual_testbed") == args.virtual, "Existing run uses a different clock mode")
        else:
            module = "network.testbed.virtual_capture" if args.virtual else "network.testbed.collect"
            command = [sys.executable, "-m", module, "--plan", str(plan_path), "--out", str(directory)]
            if args.virtual:
                command.extend(("--start", str(virtual_start(args.start, plan["session_id"]))))
            if args.smoke:
                command.append("--smoke")
            subprocess.run(command, check=True)
        if not (directory / "zeek" / "telemetry.jsonl").exists():
            subprocess.run([sys.executable, "-m", "ml", "extract", "--pcap", str(directory / "capture.pcap"),
                            "--out", str(directory / "zeek"), "--zeek", args.zeek], check=True)


if __name__ == "__main__":
    main()

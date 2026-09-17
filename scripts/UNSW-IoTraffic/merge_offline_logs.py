"""
merge_offline_logs.py

Merges multiple per-device offline traffic dumps (from device_agent.py
--mode offline) into one chronologically-sorted household event log --
the shape your Zeek/Neo4j graph-construction step expects.

Usage:
    python merge_offline_logs.py --inputs *_traffic.json --out household_traffic.json
"""

import argparse
import glob
import json


def main():
    parser = argparse.ArgumentParser(description="Merge per-device offline traffic logs into one sorted household log.")
    parser.add_argument("--inputs", nargs="+", required=True, help="Per-device JSON files or glob patterns.")
    parser.add_argument("--out", default="household_traffic.json")
    args = parser.parse_args()

    files = []
    for pattern in args.inputs:
        matched = glob.glob(pattern)
        files.extend(matched if matched else [pattern])

    all_flows = []
    for f in files:
        with open(f) as fh:
            flows = json.load(fh)
        all_flows.extend(flows)
        print(f"  {f}: {len(flows)} flows")

    all_flows.sort(key=lambda f: f["timestamp"])

    with open(args.out, "w") as f:
        json.dump(all_flows, f, indent=2)

    print(f"\nMerged {len(files)} file(s), {len(all_flows)} total flows -> {args.out}")


if __name__ == "__main__":
    main()

"""
injected_anomaly_check.py

Sanity check for the deviation scorer: synthesise windows that look like the
four target attack classes, score them against a real frozen profile, and
check that the score rises and that the *right* component drives it.

This is not an evaluation of detection performance -- that needs real attack
traffic in the testbed (Stage 4). It answers a narrower question that has to
hold first: does the scorer respond to the thing each component was written
for, or does it happen to fire on everything?

Each synthetic window is built by taking a typical (median) window for the
device and changing only what the attack would change:

  port_scan         many never-seen destinations, mostly failed TCP
  lateral_movement  a handful of never-seen LAN destinations on new ports
  exfiltration      normal destination count, hugely inflated upload volume
  c2_beacon         one never-seen domain, tiny and regular traffic

Usage:
    python profiling/validation/injected_anomaly_check.py \
        --profile data/processed/unsw/behavioral_profiles/AmazonEcho.json \
        --windows data/processed/unsw/features/AmazonEcho/windows.jsonl
"""

import argparse
import copy
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "profile_engine"))

from score_window import load_profile, score_window  # noqa: E402


def typical_window(windows):
    """A median-ish window: the one whose flow count is closest to the median."""
    counts = [w.get("flow_count", 0) for w in windows]
    target = statistics.median(counts)
    return copy.deepcopy(min(windows, key=lambda w: abs(w.get("flow_count", 0) - target)))


def port_scan(window):
    """One device sweeping the LAN: many new destinations, most refusing."""
    scanned = [f"10.0.0.{n}" for n in range(20, 60)]
    window["destinations"] = scanned
    window["unique_destinations"] = len(scanned)
    window["flow_count"] = len(scanned)
    window["destination_ports"] = [f"tcp/{p}" for p in (22, 23, 80, 443, 445, 8080)]
    window["tcp_failed_ratio"] = 0.95
    window["service_distribution"] = {"unknown": 1.0}
    return window


def lateral_movement(window):
    """Reaching sideways to a few peers it has never spoken to."""
    peers = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]
    window["destinations"] = peers
    window["unique_destinations"] = len(peers)
    window["flow_count"] = 6
    window["destination_ports"] = ["tcp/22", "tcp/445"]
    window["tcp_failed_ratio"] = 0.5
    return window


def exfiltration(window):
    """Normal-looking contact, abnormal amount of data leaving."""
    window["destinations"] = ["203.0.113.47"]
    window["unique_destinations"] = 1
    window["orig_bytes"] = 500_000_000
    window["bytes_total"] = 500_000_000
    window["packets_total"] = 400_000
    return window


def c2_beacon(window):
    """A quiet, regular check-in with somewhere new."""
    window["destinations"] = ["198.51.100.23"]
    window["unique_destinations"] = 1
    window["domains"] = ["cdn-update-service.example.net"]
    window["unique_domains"] = 1
    window["flow_count"] = 2
    window["bytes_total"] = 320
    window["interflow_gap_variance"] = 0.0001
    return window


SCENARIOS = {
    "port_scan": port_scan,
    "lateral_movement": lateral_movement,
    "exfiltration": exfiltration,
    "c2_beacon": c2_beacon,
}

# The component each scenario is supposed to trip. A scenario that scores high
# via some unrelated component is a scorer that got the right answer by luck.
EXPECTED_DRIVER = {
    "port_scan": {"new_destinations", "failed_conns"},
    "lateral_movement": {"new_destinations", "new_ports"},
    "exfiltration": {"volume"},
    "c2_beacon": {"new_domains", "new_destinations"},
}


def main():
    parser = argparse.ArgumentParser(
        description="Score synthetic attack windows against a frozen profile."
    )
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--windows", required=True, type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    profile = load_profile(args.profile)
    with args.windows.open() as handle:
        windows = [json.loads(line) for line in handle if line.strip()]

    baseline_window = typical_window(windows)
    baseline = score_window(profile, baseline_window)
    calibration = (profile.get("calibration") or {}).get("baseline_scores", {})

    print(f"{profile['device']}")
    print(f"  baseline p99 score (training windows): {calibration.get('p99', float('nan')):.3f}")
    print(f"  typical window scores {baseline['deviation_score']:.3f}\n")

    failures = []
    for name, build in SCENARIOS.items():
        scored = score_window(profile, build(copy.deepcopy(baseline_window)))
        drivers = sorted(
            ((v, k) for k, v in scored["components"].items() if v > 0), reverse=True
        )
        driver_names = {k for _v, k in drivers}
        detected = scored["deviation_score"] > args.threshold
        expected_hit = bool(driver_names & EXPECTED_DRIVER[name])

        status = "ok " if (detected and expected_hit) else "BAD"
        if status == "BAD":
            failures.append(name)
        shown = ", ".join(f"{k}={v:.2f}" for v, k in drivers[:3]) or "nothing"
        print(f"  [{status}] {name:17s} score={scored['deviation_score']:.3f}  {shown}")

    print()
    if failures:
        print(f"  scenarios not detected or driven by the wrong component: {failures}")
        return 1
    print("  all scenarios detected, each via an expected component")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

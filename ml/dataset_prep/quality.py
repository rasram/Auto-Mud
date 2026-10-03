"""Capture quality and distribution summaries; usable before training."""
from collections import defaultdict
import numpy as np

from ml.schema import FEATURES, read_json, read_jsonl, write_json
from ml.graph.build import build_snapshots


def inspect_capture(manifest_path, telemetry_path, out, reference=None):
    manifest = read_json(manifest_path)
    # Diagnostics must remain usable before a human certifies capture completeness.
    # Retain declared outages, and never change the persisted training manifest.
    diagnostic_manifest = {**manifest, "capture_complete": True}
    observations, edges = defaultdict(lambda: defaultdict(list)), defaultdict(int)
    summaries = defaultdict(lambda: {"active_windows": 0, "available_windows": 0})
    telemetry = (r for r in read_jsonl(telemetry_path) if manifest["start"] <= r["window_start"] < manifest["end"])
    for g in build_snapshots(telemetry, diagnostic_manifest):
        for n in g["nodes"]:
            s = summaries[n["device_id"]]
            s["available_windows"] += n["available"]
            s["active_windows"] += n["active"] and n["available"]
            if n["available"] and n["active"]:
                for name, value, valid in zip(FEATURES, n["features"], n["feature_mask"]):
                    if valid:
                        observations[n["device_id"]][name].append(value)
        for e in g["edges"]:
            pair = g["nodes"][e["source"]]["device_id"] + " -> " + g["nodes"][e["target"]]["device_id"]
            edges[pair] += 1
    report = {"run_id": manifest["run_id"], "capture_complete": manifest["capture_complete"],
              "capture_drops": manifest.get("capture_drops"), "devices": {}, "edge_windows": dict(edges), "warnings": []}
    if not manifest["capture_complete"]:
        report["warnings"].append("Uncertified capture: statistics describe observed traffic only; not training approval")
    for d, summary in summaries.items():
        report["devices"][d] = {**summary, "features": {f: {"count": len(v), "mean": float(np.mean(v)),
            "p50": float(np.percentile(v, 50)), "p95": float(np.percentile(v, 95))} for f, v in observations[d].items()}}
        if not summary["active_windows"]:
            report["warnings"].append(f"{d}: no active observations; check mapping/capture")
        failed = observations[d].get("tcp_failed_fraction", [])
        if manifest["normal"] and failed and np.mean(failed) > 0.2:
            report["warnings"].append(f"{d}: over 20% mean TCP establishment failure in normal traffic")
    if reference:
        ref = read_json(reference)
        comparisons = {}
        for d, info in report["devices"].items():
            before = ref.get("devices", {}).get(d, {}).get("features", {})
            comparisons[d] = {f: {"pilot_p50": v["p50"], "reference_p50": before[f]["p50"],
                "pilot_p95": v["p95"], "reference_p95": before[f]["p95"]}
                for f, v in info["features"].items() if f in before}
        report["comparison"] = comparisons
    write_json(out, report)
    return report

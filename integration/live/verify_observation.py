"""Read-only engineering observation acceptance; never enables enforcement."""
import argparse
import hashlib
import json
import math
import time
from collections import Counter
from pathlib import Path
from urllib.request import urlopen

from integration.live.common import atomic_json
from integration.live.config import active_binding, load_deployment
from integration.live.dashboard import _payload, _traces
from integration.live.finalizer import _runtime_process_active


def verify(deployment, output, minimum_windows=3, minimum_history=0):
    root = Path(deployment["paths"]["runtime_root"])
    runtime = json.loads((root / "current.json").read_text())
    assert deployment["observation_kind"] == "engineering" and deployment["decision"]["mode"] == "observe"
    assert _runtime_process_active(runtime), "Runtime process is stopped"
    raw = Path(deployment["paths"]["event_log"]).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    traces = [row for row in _traces(rows) if row["run_id"] == runtime["run_id"]]
    complete = [row for row in traces if row["health"]["sensor"] == "healthy" and row["health"]["joined"]]
    assert len(complete) >= minimum_windows, f"Only {len(complete)} complete joined windows"
    assert traces[0] is complete[0], "Newest evidence is incomplete"
    assert time.time() - complete[0]["window_end"] < deployment["gnn"].get("stale_after_seconds", 180)
    for previous, following in zip(complete[1:minimum_windows], complete[:minimum_windows-1]):
        assert following["window_start"] - previous["window_start"] == 60, "Nonconsecutive observation windows"
    with urlopen(deployment["network"]["controller_api"].rstrip("/") + "/v1/switches", timeout=5) as response:
        switches = json.load(response)["switches"]
    switch = next(row for row in switches if row["dpid"] == deployment["network"]["dpid"])
    for device in deployment["devices"]:
        binding = active_binding(deployment, device["device_id"], complete[0]["window_start"])
        assert switch["bindings"].get(binding["mac"]) == binding["switch_port"], "Controller binding mismatch"
    samples = []
    for trace in complete[:minimum_windows]:
        assert trace["sensor_id"] == deployment["network"]["sensor_id"]
        assert trace["inventory_version"] == deployment["inventory_version"]
        assert trace["session_id"] == runtime["session_id"]
        assert trace["health"]["gnn"] == trace["health"]["mud"] == "available"
        assert not trace["health"]["gnn_detail"].get("identity_unscored_device_ids")
        gnn = _payload(trace["events"], "gnn_evidence")
        assert len(gnn["devices"]) == len(deployment["devices"])
        scores = []
        for device in gnn["devices"]:
            assert device["status"] == "ok", f"Unscored active probe device: {device['device_id']}"
            for head, value, flag in (("a", "behavioral_score", "behavioral_flag"), ("b", "link_anomaly", "link_flag")):
                assert device.get(value) is not None and math.isfinite(device[value])
                threshold = device["calibration_scope"][head]["value"]
                assert device[flag] == (device[value] > threshold), "Frozen cutoff decision mismatch"
            scores.append({key: device.get(key) for key in (
                "device_id", "status", "behavioral_score", "behavioral_flag", "link_anomaly", "link_flag",
                "calibration_scope", "history", "unscored_reasons",
            )})
        if trace is complete[0]:
            assert min(row["history"]["prior_windows"] for row in scores) >= minimum_history, "History not yet warm"
        mud = _payload(trace["events"], "mud_evidence")
        permissions = Counter(row["permission"] for row in mud["exchanges"])
        assert permissions["allowed"] >= 6 and permissions["denied"] >= 12
        assert not trace["decision"]["enforcement_eligible"]
        assert trace["action"] is None, "Unexpected controller action during engineering observation"
        samples.append({
            "trace_id": trace["trace_id"], "window_start": trace["window_start"], "window_end": trace["window_end"],
            "health": trace["health"], "model": trace["model"], "mud_policy": trace["mud_policy"],
            "permissions": dict(permissions), "devices": scores, "latency_seconds": trace["latency_seconds"],
        })
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "events-snapshot.jsonl").write_bytes(raw)
    report = {
        "schema_version": "automud.engineering-observation-check.v1", "status": "passed", "checked_at": time.time(),
        "runtime": runtime, "switches": switches, "complete_windows_retained": len(complete),
        "sampled_consecutive_windows": minimum_windows, "required_prior_windows": minimum_history,
        "events_snapshot_sha256": hashlib.sha256(raw).hexdigest(), "windows": samples,
        "limitations": "Controlled isolated lab probes; not representative accuracy or production/enforcement acceptance.",
    }
    atomic_json(output / "observation-check.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--minimum-windows", type=int, default=3)
    parser.add_argument("--minimum-history", type=int, default=0)
    args = parser.parse_args()
    if args.minimum_windows < 1 or args.minimum_history < 0:
        parser.error("Invalid window/history requirement")
    report = verify(load_deployment(args.config), args.output, args.minimum_windows, args.minimum_history)
    print(json.dumps({key: report[key] for key in ("status", "complete_windows_retained", "sampled_consecutive_windows", "required_prior_windows")}))


if __name__ == "__main__":
    main()

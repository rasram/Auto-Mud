"""Read-only audit of retained lab flags; not an accuracy or training workflow."""
import argparse
import hashlib
import json
import math
import time
from collections import Counter, defaultdict
from pathlib import Path

from integration.live.common import atomic_json
from integration.live.config import load_deployment
from integration.live.dashboard import _payload, _traces
from integration.live.mud import MUDEngine


def flag_errors(devices):
    errors = []
    for device in devices:
        for head, score, flag in (("a", "behavioral_score", "behavioral_flag"), ("b", "link_anomaly", "link_flag")):
            value, actual = device.get(score), device.get(flag)
            if value is None:
                if actual is not None:
                    errors.append([device["device_id"], head, "flag_without_score"])
                continue
            threshold = ((device.get("calibration_scope") or {}).get(head) or {}).get("value")
            if threshold is None or not math.isfinite(value) or not math.isfinite(threshold):
                errors.append([device["device_id"], head, "invalid_score_or_threshold"])
            elif type(actual) is not bool or actual != (value > threshold):
                errors.append([device["device_id"], head, "strict_cutoff_mismatch"])
    return errors


def audit(deployment, state_path, output):
    if deployment["observation_kind"] != "engineering":
        raise ValueError("This audit is for retained engineering observations")
    import torch
    from ml.inference import GNNBundle
    torch.set_num_threads(1)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    event_bytes = Path(deployment["paths"]["event_log"]).read_bytes()
    state_bytes = Path(state_path).read_bytes()
    runtime_bytes = (Path(deployment["paths"]["runtime_root"]) / "current.json").read_bytes()
    for name, content in (("events.jsonl", event_bytes), ("state.json", state_bytes), ("runtime.json", runtime_bytes)):
        (output / name).write_bytes(content)
    runtime, state = json.loads(runtime_bytes), json.loads(state_bytes)
    traces = _traces([json.loads(line) for line in event_bytes.splitlines() if line.strip()])
    traces = [row for row in traces if row["run_id"] == runtime["run_id"]]
    errors, summary, per_device = [], [], defaultdict(Counter)
    mud_engine = MUDEngine(deployment)
    from network.testbed.live_probe import probe_plan
    by_id = {row["device_id"]: row for row in deployment["devices"]}
    planned_tcp = {(by_id[source]["ip"], address, port) for source, targets in probe_plan(deployment).items() for address, port in targets}
    allowed_tcp = {(by_id[row["initiator"]]["ip"], by_id[row["responder"]]["ip"], row["service_port"])
                   for row in mud_engine.policy.get("permissions", [])
                   if row.get("proto") == "tcp" and row.get("initiator") in by_id and row.get("responder") in by_id}
    for trace in traces:
        window = _payload(trace["events"], "window")
        gnn = _payload(trace["events"], "gnn_evidence")
        mud = _payload(trace["events"], "mud_evidence")
        errors.extend(flag_errors(gnn.get("devices") or []))
        expected = mud_engine.evaluate(window)
        recorded = {row["flow_uid"]: row["permission"] for row in mud.get("exchanges", [])}
        recomputed = {row["flow_uid"]: row["permission"] for row in expected.get("exchanges", [])}
        if recorded != recomputed:
            errors.append([trace["trace_id"], "mud", "recomputed_permissions_differ"])
        for flow in window.get("telemetry", []):
            route = (flow.get("orig_h"), flow.get("resp_h"), flow.get("resp_p"))
            if flow.get("proto") == "tcp" and route in planned_tcp:
                expected_permission = "allowed" if route in allowed_tcp else "denied"
                if recorded.get(flow.get("uid")) != expected_permission:
                    errors.append([flow.get("uid"), "mud_plan", "known_lab_permission_mismatch"])
        permissions = Counter(recorded.values())
        denied = [row for row in mud.get("exchanges", []) if row["permission"] == "denied"]
        routes = {(row.get("initiator_device_id"), row.get("responder_device_id"), row.get("proto"), row.get("service_port")) for row in denied}
        ring_only = all(row.get("proto") == "tcp" and row.get("service_port") == 18080 for row in denied)
        unexpected_tcp = [row.get("uid") for row in window.get("telemetry", [])
                          if row.get("proto") == "tcp" and (row.get("orig_h"), row.get("resp_h"), row.get("resp_p")) not in planned_tcp]
        for row in gnn.get("devices", []):
            per_device[row["device_id"]]["scored_windows"] += row.get("behavioral_score") is not None
            per_device[row["device_id"]]["behavior_flags"] += row.get("behavioral_flag") is True
            per_device[row["device_id"]]["connection_flags"] += row.get("link_flag") is True
        summary.append({"window_start": trace["window_start"], "trace_id": trace["trace_id"],
                        "health": trace["health"], "permissions": dict(permissions),
                        "denied_connections": len(denied), "denied_routes": len(routes),
                        "denials_only_port_18080": ring_only,
                        "unplanned_tcp_flow_ids": unexpected_tcp,
                        "a_flags": trace["counts"]["behavioral_flags"], "b_flags": trace["counts"]["link_flags"]})
    stream = max((row for row in state["streams"].values() if row["last_response"]["run_id"] == runtime["run_id"]),
                 key=lambda row: row["last_response"]["window_start"])
    bundle = GNNBundle(Path(state["active"]["path"]), "cpu", allow_candidate=True)
    bundle.verify_inputs()
    original = stream["last_response"]
    replay = bundle.score_graph(stream["last_graph"])
    replay_devices = {row["device_id"]: row for row in replay["devices"]}
    maximum_error, compared_scores, score_details = 0.0, 0, []
    for row in original["devices"]:
        other = replay_devices[row["device_id"]]
        for score, flag in (("behavioral_score", "behavioral_flag"), ("link_anomaly", "link_flag")):
            if row[score] is None or other[score] is None:
                if row[score] != other[score]:
                    errors.append([row["device_id"], score, "replay_availability_mismatch"])
                continue
            difference = abs(row[score] - other[score])
            maximum_error = max(maximum_error, difference)
            compared_scores += 1
            if difference > 1e-4 or row[flag] != other[flag]:
                errors.append([row["device_id"], score, "replay_mismatch"])
        score_details.append({key: row.get(key) for key in (
            "device_id", "behavioral_score", "behavioral_flag", "link_anomaly", "link_flag", "history", "calibration_scope")})
    bundle.verify_inputs()
    report = {"schema_version": "automud.observation-audit.v1", "checked_at": time.time(),
              "status": "passed" if not errors else "failed", "accuracy_validated": False, "run_id": runtime["run_id"],
              "traffic_kind": runtime.get("traffic_kind"), "windows_checked": len(summary),
              "errors": errors, "latest_windows": summary[:10], "per_device": dict(per_device),
              "replay": {"window_start": original["window_start"], "compared_scores": compared_scores,
                         "maximum_absolute_error": maximum_error, "devices": score_details},
              "source_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in
                                (("events.jsonl", event_bytes), ("state.json", state_bytes), ("runtime.json", runtime_bytes))},
              "conclusion": {
                  "computation": "Frozen cutoff decisions, same-input replay and lab MUD evaluation audited separately.",
                  "ground_truth": "Unavailable for behavioral anomalies; no attack-labelled representative capture was supplied.",
                  "policy_denials": "Port-18080 ring probes are deliberate lab policy violations, not evidence of compromise.",
                  "gnn_flags": "Unconfirmed signals on controlled lab probes. True/false-positive accuracy cannot be inferred.",
                  "scope": "No training, new samples, threshold changes, live API submissions or live-state writes."}}
    atomic_json(output / "audit.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--state", default="/mnt/data/automud/tmp/gnn-live-supervised/state.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = audit(load_deployment(args.config), args.state, args.output)
    print(json.dumps({"status": result["status"], "windows_checked": result["windows_checked"],
                      "errors": result["errors"], "compared_scores": result["replay"]["compared_scores"],
                      "maximum_score_error": result["replay"]["maximum_absolute_error"]}))
    raise SystemExit(0 if result["status"] == "passed" else 1)

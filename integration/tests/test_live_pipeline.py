import copy
import json

import pytest

from integration.live.config import load_deployment
from integration.live.decision import DecisionEngine
from integration.live.finalizer import build_window
from integration.live.join import join_evidence
from integration.live.mud import MUDEngine, unavailable_mud


CONFIG = "configs/live/saturn.json"


def window(rows=None, kind="engineering"):
    deployment = load_deployment(CONFIG)
    return {
        "schema_version": "automud.live-window.v1", "observation_kind": kind,
        "run_id": "run-1", "session_id": "session-1", "sensor_id": "saturn-zeek-1",
        "inventory_version": deployment["inventory_version"],
        "window_start": 60, "window_end": 120, "watermark": 120,
        "inventory": [],
        "health": {"complete": True, "sensor_healthy": True, "clock_synchronized": True,
                   "capture_drops": 0, "unavailable_device_ids": []},
        "telemetry": rows or [],
    }


def flow(uid, source, destination, port):
    return {
        "schema_version": "automud.graph.v1", "window_start": 60, "uid": uid,
        "orig_h": source, "resp_h": destination, "orig_p": 40000, "resp_p": port,
        "proto": "tcp", "flow_start": 61, "orig_ip_bytes": 100, "resp_ip_bytes": 80,
        "orig_pkts": 2, "resp_pkts": 2, "observed_duration": 1.0,
        "established": True, "failed": False, "new_flow": True, "tcp_syn_observed": True,
    }


def gnn_evidence(w, link_flag=True):
    return {
        "schema_version": "automud.gnn-evidence.v1",
        **{name: w[name] for name in ("observation_kind", "run_id", "session_id", "sensor_id", "inventory_version", "window_start", "window_end")},
        "observation_id": "a" * 64,
        "devices": [{"device_id": "AmazonEcho_44650d56ccd3_flows", "link_flag": link_flag,
                     "behavioral_flag": False}],
        "health": dict(w["health"]),
    }


def test_mud_distinguishes_allowed_forbidden_unknown_and_outage():
    deployment = load_deployment(CONFIG)
    w = window([
        flow("allowed", "10.0.0.11", "10.0.0.20", 8080),
        flow("denied", "10.0.0.11", "10.0.0.20", 22),
        flow("unknown", "10.0.0.250", "10.0.0.20", 22),
    ])
    evidence = MUDEngine(deployment, now=lambda: 130).evaluate(w)
    assert [row["permission"] for row in evidence["exchanges"]] == ["allowed", "denied", "unknown_device"]
    outage = unavailable_mud(w, evidence["policy_version"], "test outage", now=lambda: 130)
    assert outage["health"] == {"available": False, "reason": "test outage", "evaluated_at": 130}
    retried = MUDEngine(deployment, now=lambda: 140).evaluate(w)
    assert retried["evidence_id"] == evidence["evidence_id"]


def test_join_rejects_cross_window_and_decision_withholds_engineering_action():
    deployment = load_deployment(CONFIG)
    w = window([flow("denied", "10.0.0.11", "10.0.0.20", 22)])
    mud = MUDEngine(deployment, now=lambda: 130).evaluate(w)
    gnn = gnn_evidence(w)
    joined = join_evidence(w, gnn, mud, now=lambda: 131)
    decision = DecisionEngine(deployment, now=lambda: 132).decide(joined)
    assert decision["proposals"][0]["tier"] == "block"
    assert not decision["enforcement_eligible"]
    assert "engineering_observation" in decision["withheld_reasons"]
    wrong = copy.deepcopy(gnn)
    wrong["window_start"] = 120
    with pytest.raises(ValueError, match="Cross-window"):
        join_evidence(w, wrong, mud)


def test_finalizer_emits_silent_healthy_window_and_marks_missing_health_unavailable(tmp_path):
    deployment = load_deployment(CONFIG)
    telemetry = tmp_path / "automud-window.log"
    health = tmp_path / "automud-health.log"
    telemetry.write_text("")
    health.write_text(json.dumps({
        "window_start": 60, "watermark": 120, "complete": True,
        "sensor_healthy": True, "clock_synchronized": True, "capture_drops": 0,
        "unavailable_device_ids": [],
    }) + "\n")
    healthy = build_window(deployment, telemetry, health, 60, "run-1", "session-1")
    assert healthy["telemetry"] == []
    assert healthy["health"]["complete"]
    missing = build_window(deployment, telemetry, health, 120, "run-1", "session-1")
    assert not missing["health"]["complete"]
    assert missing["health"]["capture_drops"] is None


def test_finalizer_uses_recorded_runtime_lease_start(tmp_path):
    deployment = load_deployment(CONFIG)
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    telemetry = zeek / "automud-window.log"
    health = zeek / "automud-health.log"
    telemetry.write_text("")
    health.write_text(json.dumps({
        "window_start": 120, "watermark": 180, "complete": True,
        "sensor_healthy": True, "clock_synchronized": True, "capture_drops": 0,
    }) + "\n")
    (tmp_path / "runtime.json").write_text(json.dumps({
        "run_id": "run-1", "inventory_version": deployment["inventory_version"], "started_at": 91,
    }))
    completed = build_window(deployment, telemetry, health, 120, "run-1", "session-1")
    assert {address["start"] for device in completed["inventory"] for address in device["addresses"]} == {91}

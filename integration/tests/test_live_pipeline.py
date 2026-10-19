import copy
import json
from pathlib import Path

import pytest

from integration.live.common import canonical_digest
from integration.live.config import bindings, interval_inventory, load_deployment
from integration.live.coordinator import JoinCoordinator
from integration.live.decision import DecisionEngine
from integration.live.dashboard import _traces
from integration.live.finalizer import DurableFinalizer, build_window
from integration.live.gnn import validate_gnn_evidence
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


def test_join_rejects_cross_window_and_decision_withholds_engineering_action(tmp_path):
    deployment = load_deployment(CONFIG)
    deployment["paths"]["state_db"] = str(tmp_path / "state.sqlite3")
    deployment["decision"]["override_file"] = None
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


def test_deadline_coordinator_handles_reordered_missing_and_late_branches(tmp_path):
    clock = [100.0]
    coordinator = JoinCoordinator(tmp_path / "join.sqlite3", join_timeout_seconds=10, now=lambda: clock[0])
    observed = window()
    key = coordinator.ingest_window(observed)
    mud = MUDEngine(load_deployment(CONFIG), now=lambda: 101).evaluate(observed)
    assert coordinator.ingest_branch(key, "mud", mud) == "accepted"
    assert coordinator.close(key) is None
    clock[0] = 111
    joined = coordinator.close_ready()[0]
    assert joined["partial"] and joined["branch_status"]["gnn"] == "unavailable"
    assert coordinator.ingest_branch(key, "gnn", gnn_evidence(observed)) == "late"
    assert coordinator.status()["late_branches"] == 1

    second = window()
    second["window_start"], second["window_end"], second["watermark"] = 120, 180, 180
    clock[0] = 120
    second_key = coordinator.ingest_window(second)
    gnn = gnn_evidence(second)
    assert coordinator.ingest_branch(second_key, "gnn", gnn) == "accepted"
    changed = copy.deepcopy(gnn)
    changed["observation_id"] = "b" * 64
    with pytest.raises(ValueError, match="Conflicting duplicate"):
        coordinator.ingest_branch(second_key, "gnn", changed)
    second_mud = MUDEngine(load_deployment(CONFIG), now=lambda: 121).evaluate(second)
    assert coordinator.ingest_branch(second_key, "mud", second_mud) == "accepted"
    assert not coordinator.close(second_key)["partial"]


def test_gnn_evidence_validation_marks_stale_and_rejects_identity_mismatch():
    observed = window()
    evidence = {
        **gnn_evidence(observed),
        "model": {"bundle_id": "1" * 64, "bundle_version": "test", "a_checkpoint": "2" * 64, "b_checkpoint": "2" * 64},
        "provenance": {"a_checkpoint": "2" * 64, "b_checkpoint": "2" * 64},
        "devices": [],
        "health": {
            **observed["health"], "identity_unscored_device_ids": [],
            "received_at": 121, "processing_seconds": 0.01,
        },
        "state": {"epoch": 1, "reset_reason": None, "reset_device_ids": [], "history": {}},
        "head_c_trained": False, "enforcement_action": None,
    }
    fresh = validate_gnn_evidence(observed, evidence, now=130, stale_after_seconds=20)
    assert fresh["integration_health"]["fresh"]
    stale = validate_gnn_evidence(observed, evidence, now=200, stale_after_seconds=20)
    assert not stale["integration_health"]["fresh"]
    wrong = copy.deepcopy(evidence)
    wrong["sensor_id"] = "other"
    with pytest.raises(ValueError, match="identity mismatch"):
        validate_gnn_evidence(observed, wrong, now=130)


def test_decision_cooldown_and_suppress_override_are_durable(tmp_path):
    deployment = load_deployment(CONFIG)
    deployment["paths"]["state_db"] = str(tmp_path / "state.sqlite3")
    policy = json.loads(Path("configs/live/decision-policy.json").read_text())
    policy["cooldown_seconds"] = 120
    policy_path = tmp_path / "decision.json"
    policy_path.write_text(json.dumps(policy))
    deployment["decision"]["policy"] = str(policy_path)
    override_path = tmp_path / "overrides.json"
    override_path.write_text(json.dumps({"schema_version": "automud.human-overrides.v1", "overrides": []}))
    deployment["decision"]["override_file"] = str(override_path)
    clock = [200.0]
    engine = DecisionEngine(deployment, now=lambda: clock[0])
    first_window = window([flow("denied", "10.0.0.11", "10.0.0.20", 22)])
    first_join = join_evidence(
        first_window, gnn_evidence(first_window), MUDEngine(deployment).evaluate(first_window), now=lambda: 130,
    )
    first = engine.decide(first_join)
    assert first["proposals"][0]["dispatch_eligible"]
    second_window = copy.deepcopy(first_window)
    second_window.update(window_start=120, window_end=180, watermark=180)
    second_window["telemetry"][0]["window_start"] = 120
    second_gnn = gnn_evidence(second_window)
    second_mud = MUDEngine(deployment).evaluate(second_window)
    clock[0] = 230
    second = engine.decide(join_evidence(second_window, second_gnn, second_mud, now=lambda: 181))
    assert second["proposals"][0]["policy_state"]["cooldown_active"]
    assert not second["proposals"][0]["dispatch_eligible"]
    override_path.write_text(json.dumps({
        "schema_version": "automud.human-overrides.v1",
        "overrides": [{
            "override_id": "maintenance", "action": "suppress",
            "actor": "operator", "reason": "approved maintenance",
            "expires_at": 1000, "target_device_id": "AmazonEcho_44650d56ccd3_flows",
        }],
    }))
    third_window = copy.deepcopy(first_window)
    third_window.update(window_start=180, window_end=240, watermark=240)
    third_window["telemetry"][0]["window_start"] = 180
    clock[0] = 400
    third = engine.decide(join_evidence(
        third_window, gnn_evidence(third_window), MUDEngine(deployment).evaluate(third_window), now=lambda: 241,
    ))
    assert third["proposals"][0]["policy_state"]["override"]["override_id"] == "maintenance"
    assert not third["proposals"][0]["dispatch_eligible"]


def test_mud_external_name_evidence_requires_valid_ttl(tmp_path):
    deployment = load_deployment(CONFIG)
    policy = json.loads(Path("configs/mud/saturn-lab-policy.json").read_text())
    policy["external_permissions"] = [{
        "initiator": "AmazonEcho_44650d56ccd3_flows", "fqdn": "api.example.test",
        "proto": "tcp", "service_port": 443, "reason": "approved test API",
    }]
    policy_path = tmp_path / "mud.json"
    policy_path.write_text(json.dumps(policy))
    deployment["_policy_path"] = str(policy_path)
    observed = window([flow("external", "10.0.0.11", "203.0.113.5", 443)])
    names = [{
        "sensor_id": observed["sensor_id"], "name": "api.example.test",
        "addresses": ["203.0.113.5"], "valid_from": 60, "valid_until": 100,
    }]
    evidence = MUDEngine(deployment).evaluate(observed, names)
    assert evidence["exchanges"][0]["permission"] == "allowed"
    expired = copy.deepcopy(names)
    expired[0]["valid_until"] = 61
    evidence = MUDEngine(deployment).evaluate(observed, expired)
    assert evidence["exchanges"][0]["permission"] == "unknown_policy"


def test_dashboard_keeps_window_and_decision_stage_times_separate():
    observed = window()
    trace_id = "trace"
    rows = [
        {"trace_id": trace_id, "kind": "window", "recorded_at": 121.0, "payload": observed},
        {"trace_id": trace_id, "kind": "joined_evidence", "recorded_at": 125.0, "payload": {}},
        {"trace_id": trace_id, "kind": "decision", "recorded_at": 126.0, "payload": {"decision_id": "d"}},
    ]
    trace = _traces(rows)[0]
    assert trace["latency_seconds"]["window_close_to_join"] == 5.0
    assert trace["latency_seconds"]["join_to_decision"] == 1.0


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


def test_v2_inventory_resolves_time_bounded_rebinding(tmp_path):
    value = json.loads(Path(CONFIG).read_text())
    value["schema_version"] = "automud.deployment.v2"
    for index, device in enumerate(value["devices"], 1):
        device["bindings"] = [{
            "ip": device.pop("ip"), "mac": device.pop("mac"),
            "switch_port": device.pop("switch_port", index),
            "valid_from": 0, "valid_until": None,
        }]
    first = value["devices"][0]
    first["bindings"][0]["valid_until"] = 120
    first["bindings"].append({
        "ip": "10.0.0.30", "mac": first["bindings"][0]["mac"],
        "switch_port": 30, "valid_from": 120, "valid_until": None,
    })
    value["mud"]["policy"] = str(Path("configs/mud/saturn-lab-policy.json").resolve())
    config = tmp_path / "v2.json"
    config.write_text(json.dumps(value))
    deployment = load_deployment(config)
    assert bindings(deployment, at=119)[1][first["device_id"]]["ip"] == "10.0.0.11"
    assert bindings(deployment, at=120)[1][first["device_id"]]["ip"] == "10.0.0.30"
    addresses = next(
        row["addresses"] for row in interval_inventory(deployment, 60, 180)
        if row["device_id"] == first["device_id"]
    )
    assert [row["ip"] for row in addresses] == ["10.0.0.11", "10.0.0.30"]
    assert [row["start"] for row in addresses] == [0, 120]
    conflicting = copy.deepcopy(value)
    conflicting["devices"][1]["bindings"][0]["ip"] = "10.0.0.30"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(conflicting))
    with pytest.raises(ValueError, match="Conflicting live binding"):
        load_deployment(bad)


def test_finalizer_uses_watermark_then_deadline_for_missing_health(tmp_path):
    deployment = load_deployment(CONFIG)
    deployment["paths"].update({
        "queue": str(tmp_path / "queue"), "state_db": str(tmp_path / "state.sqlite3"),
        "event_log": str(tmp_path / "events.jsonl"),
    })
    run = tmp_path / "run"
    zeek = run / "zeek"
    zeek.mkdir(parents=True)
    telemetry = zeek / "automud-window.log"
    health = zeek / "automud-health.log"
    telemetry.write_text("")
    health.write_text(json.dumps({
        "window_start": 60, "watermark": 120, "complete": False,
        "sensor_healthy": True, "clock_synchronized": True, "capture_drops": 0,
    }) + "\n")
    (run / "runtime.json").write_text(json.dumps({
        "run_id": "run-1", "session_id": "session-1", "started_at": 61,
        "active": True,
        "inventory_version": deployment["inventory_version"],
        "telemetry_log": str(telemetry), "health_log": str(health),
    }))
    clock = [200.0]
    finalizer = DurableFinalizer(
        deployment, telemetry, health, "run-1", "session-1", now=lambda: clock[0],
    )
    assert finalizer.eligible_windows(incomplete_deadline_seconds=30) == [60]
    clock[0] = 220
    assert finalizer.eligible_windows(incomplete_deadline_seconds=30) == [60, 120]


def test_finalizer_stops_at_runtime_boundary_and_isolates_run_queues(tmp_path):
    deployment = load_deployment(CONFIG)
    deployment["paths"].update({
        "queue": str(tmp_path / "queue"), "state_db": str(tmp_path / "state.sqlite3"),
        "event_log": str(tmp_path / "events.jsonl"),
    })
    run = tmp_path / "run"
    zeek = run / "zeek"
    zeek.mkdir(parents=True)
    telemetry = zeek / "automud-window.log"
    health = zeek / "automud-health.log"
    telemetry.write_text("")
    health.write_text(json.dumps({
        "window_start": 60, "watermark": 120, "complete": True,
        "sensor_healthy": True, "clock_synchronized": True, "capture_drops": 0,
    }) + "\n")
    (run / "runtime.json").write_text(json.dumps({
        "run_id": "run-1", "session_id": "session-1", "started_at": 61,
        "stopped_at": 125, "active": False,
        "inventory_version": deployment["inventory_version"],
        "telemetry_log": str(telemetry), "health_log": str(health),
    }))
    first = DurableFinalizer(deployment, telemetry, health, "run-1", "session-1", now=lambda: 500)
    second = DurableFinalizer(deployment, telemetry, health, "run-2", "session-2", now=lambda: 500)
    assert first.eligible_windows(incomplete_deadline_seconds=30) == [60]
    assert first.run_queue != second.run_queue


def test_finalizer_preserves_exact_pending_payload_across_restart(tmp_path):
    deployment = load_deployment(CONFIG)
    deployment["paths"].update({
        "queue": str(tmp_path / "queue"), "state_db": str(tmp_path / "state.sqlite3"),
        "event_log": str(tmp_path / "events.jsonl"),
    })
    deployment["decision"]["override_file"] = None
    run = tmp_path / "run"
    zeek = run / "zeek"
    zeek.mkdir(parents=True)
    telemetry = zeek / "automud-window.log"
    health = zeek / "automud-health.log"
    telemetry.write_text("")
    health.write_text(json.dumps({
        "window_start": 60, "watermark": 120, "complete": True,
        "sensor_healthy": True, "clock_synchronized": True, "capture_drops": 0,
    }) + "\n")
    (run / "runtime.json").write_text(json.dumps({
        "run_id": "run-1", "session_id": "session-1", "started_at": 61,
        "stopped_at": 125, "active": False,
        "inventory_version": deployment["inventory_version"],
        "telemetry_log": str(telemetry), "health_log": str(health),
    }))
    first = DurableFinalizer(deployment, telemetry, health, "run-1", "session-1", now=lambda: 200)

    def fail(*_args, **_kwargs):
        raise TimeoutError("injected branch outage")

    first.orchestrator.process = fail
    with pytest.raises(TimeoutError, match="injected branch outage"):
        first.finalize(60)
    pending = first.pending / "60.json"
    original = pending.read_bytes()
    restarted = DurableFinalizer(deployment, telemetry, health, "run-1", "session-1", now=lambda: 201)
    restarted.orchestrator.process = lambda *_args, **_kwargs: {"status": "complete", "actions": []}
    result = restarted.finalize(60)
    assert result["status"] == "complete"
    assert not pending.exists()
    assert (restarted.accepted / "60.json").exists()
    assert canonical_digest(json.loads(original)) == restarted._status["attempts"]["60"]["payload_hash"]

from pathlib import Path

from scapy.utils import PcapReader

from ml.schema import read_json, read_jsonl, validate_manifest, write_json
from network.testbed.collection_plan import build_plan
from network.testbed.virtual_capture import render
from scripts.collect_gnn_matrix import virtual_start


TOPOLOGY = Path(__file__).resolve().parents[2] / "network" / "testbed" / "topology.json"


def test_virtual_capture_preserves_logical_time_and_actor_labels(tmp_path):
    topology = read_json(TOPOLOGY)
    actor = topology["devices"][0]
    plan = build_plan(topology, duration=600, seed=3, scenario="port_scan", actor=actor)
    path = tmp_path / "plan.json"
    write_json(path, plan)
    start = 1704067200
    result = render(path, tmp_path / "capture", start, smoke=True)
    manifest = validate_manifest(read_json(tmp_path / "capture" / "manifest.json"), training=True)
    assert manifest["source"] == "virtual_testbed"
    assert manifest["synthetic"] and manifest["clock_mode"] == "virtual_packet_time"
    assert result["virtual_seconds"] == 600 and result["packets"] > len(plan["events"])
    labels = list(read_jsonl(tmp_path / "capture" / "labels.jsonl"))
    assert [r for r in labels if r["label"] == 1][0]["device_id"] == actor
    with PcapReader(str(tmp_path / "capture" / "capture.pcap")) as reader:
        times = [float(packet.time) for packet in reader]
    assert times == sorted(times)
    assert start <= times[0] and times[-1] < start + 610


def test_virtual_scenario_phase_is_deterministic_and_auditable(tmp_path):
    topology = read_json(TOPOLOGY)
    actor = topology["devices"][0]
    plan = build_plan(topology, duration=600, seed=4, scenario="beaconing", actor=actor)
    path = tmp_path / "plan.json"
    write_json(path, plan)
    anchor = 1704067200
    assert virtual_start(anchor, plan["session_id"]) == virtual_start(anchor, plan["session_id"])
    assert 0 <= virtual_start(anchor, plan["session_id"]) - anchor < 86400
    start = anchor + 3600
    render(path, tmp_path / "capture", start, smoke=True)
    manifest = read_json(tmp_path / "capture" / "manifest.json")
    executed = read_json(tmp_path / "capture" / "executed-plan.json")
    assert executed["utc_phase"] == 3600
    assert manifest["executed_plan_sha256"] != manifest["plan_sha256"]

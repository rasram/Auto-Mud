import pytest

from ml.schema import VERSION, read_json, write_json, write_jsonl
from ml.dataset_prep.quality import inspect_capture
from ml.dataset_prep.traffic_profiles import calibrate_traffic
from ml.dataset_prep.public_manifest import make_manifest
from ml.dataset_prep.inventory import attack_workbook, unsw_attack_identities, capture_start
from ml.dataset_prep.configure import make_normal_config


def test_normal_only_config_has_chronological_stage_one_splits(tmp_path):
    start = 1704067200
    run = tmp_path / "normal"
    write_json(run / "manifest.json", {"start": start, "end": start + 7 * 86400})
    make_normal_config(run, tmp_path / "normal-sources.json")
    source = read_json(tmp_path / "normal-sources.json")["sources"][0]
    rules = {r["name"]: (r["start"], r["end"]) for r in source["partitions"]}
    assert rules["stage1_train"] == (start, start + 4 * 86400)
    assert rules["stage1_val"] == (start + 4 * 86400, start + 5 * 86400)
    assert rules["calibration"] == (start + 5 * 86400, start + 6 * 86400)
    assert rules["normal_test"] == (start + 6 * 86400, start + 7 * 86400)


def capture(tmp_path):
    m = {"schema_version": VERSION, "run_id": "public", "session_id": "public", "source": "unsw_normal",
         "start": 120, "end": 300, "normal": True, "capture_complete": True, "replay_speed": 1,
         "inventory": [{"device_id": "a", "device_type": "hub", "mac": "02:00:00:00:00:01"},
                       {"device_id": "b", "device_type": "light", "mac": "02:00:00:00:00:02"}]}
    rows = [{"schema_version": VERSION, "window_start": w, "uid": str(w) + "-" + str(i),
        "flow_start": w + i + 1, "orig_h": "10.0.0.11", "resp_h": "10.0.0.12", "proto": "tcp",
        "orig_mac": "02:00:00:00:00:01", "resp_mac": "02:00:00:00:00:02", "orig_p": 45000 + i, "resp_p": 8080,
        "orig_ip_bytes": 200, "resp_ip_bytes": 300, "orig_pkts": 3, "resp_pkts": 4,
        "observed_duration": 0.5, "established": True, "failed": False, "new_flow": True}
        for w in (60, 120, 180, 240, 300) for i in range(25)]
    write_json(tmp_path / "manifest.json", m)
    write_jsonl(tmp_path / "telemetry.jsonl", rows)
    return m, {"manifest": str(tmp_path / "manifest.json"), "telemetry": str(tmp_path / "telemetry.jsonl"), "device_ids": ["a"]}


def test_calibration_selects_complete_target_intervals(tmp_path):
    m, source = capture(tmp_path)
    m["outages"] = [{"device_id": "a", "start": 180, "end": 240}]
    write_json(source["manifest"], m)
    result = calibrate_traffic([source], tmp_path / "profiles.json")
    assert set(result["devices"]) == {"a"}
    assert result["devices"]["a"]["observed_flows"] == 50
    m["capture_complete"] = False
    write_json(source["manifest"], m)
    with pytest.raises(ValueError, match="Incomplete"):
        calibrate_traffic([source], tmp_path / "profiles.json")


def test_quality_is_available_before_certification(tmp_path):
    m, source = capture(tmp_path)
    m["capture_complete"] = False
    write_json(source["manifest"], m)
    report = inspect_capture(source["manifest"], source["telemetry"], tmp_path / "report.json")
    assert report["devices"]["a"]["active_windows"] == 3
    assert report["warnings"] and not report["capture_complete"]
    assert not read_json(source["manifest"])["capture_complete"]


def test_public_manifest_retains_review_and_evidence(tmp_path):
    m, source = capture(tmp_path)
    write_json(tmp_path / "identities.json", {"inventory": m["inventory"]})
    write_json(tmp_path / "extraction.json", {"inputs": [{"sha256": "verified-capture-hash"}]})
    make_manifest(source["telemetry"], tmp_path / "identities.json", "unsw_normal", "public",
                  tmp_path / "bootstrap.json", normal=True)
    result = read_json(tmp_path / "bootstrap.json")
    assert result["start"] == 120 and result["end"] == 300
    assert not result["capture_complete"] and result["capture_hashes"] == ["verified-capture-hash"]
    assert len(result["inventory"]) == 2
    assert result["inventory"][0]["addresses"] == [{"ip": "10.0.0.11", "start": 120, "end": 300}]


def test_unsw_workbook_roles_and_capture_clock(tmp_path):
    from openpyxl import Workbook
    from scapy.all import Ether, IP, UDP, wrpcap
    workbook = Workbook()
    targets = workbook.active
    targets.title = "Attacks"
    targets.append(["MAC", "IP", "Start Date", "End Data", "Device Type"])
    targets.append(["00:16:6c:ab:6b:88", "192.168.1.248", "2018-06-01", "2018-06-17", "Samsung Camera"])
    experiments = workbook.create_sheet("Experiments")
    experiments.append(["Attack", "Pcap File", "Annotated file name", "Layer", "Attacker", "Victim"])
    experiments.append(["TCPSYN", "18-06-01.pcap", "2018_06_01", "L2D", "192.168.1.205", "192.168.1.248"])
    workbook.save(tmp_path / "attackinfo.xlsx")
    write_json(tmp_path / "existing.json", {"inventory": []})
    info = attack_workbook(tmp_path / "attackinfo.xlsx")
    assert info["actor_ips"] == ["192.168.1.205"]
    assert not info["actor_ips_matching_listed_devices"]
    unsw_attack_identities(tmp_path / "attackinfo.xlsx", tmp_path / "identities.json", tmp_path / "existing.json")
    identity = read_json(tmp_path / "identities.json")["inventory"][0]
    assert identity["device_type"] == "camera" and identity["device_id"] == "UNSW_00166cab6b88"
    packet = Ether() / IP(src="192.168.1.205", dst="192.168.1.248") / UDP(sport=11, dport=12)
    packet.time = 1527838552
    wrpcap(str(tmp_path / "18-06-01.pcap"), [packet])
    assert capture_start(tmp_path / "18-06-01.pcap") == "2018-06-01T07:35:52+00:00"

import copy
import json
import random
from pathlib import Path

import numpy as np
import pytest
import torch
from jsonschema import validate

from ml.schema import VERSION, FEATURES, SCHEMA_HASH, HISTORY_FEATURE, MASK_OFFSET, read_json, read_jsonl, write_json, validate_manifest, validate_labels
from ml.graph.build import build_snapshots, features, label_window
from ml.dataset_prep.tensors import Normalizer, to_pyg
from ml.dataset_prep.catalog import load_partition, prepare, readiness
from ml.model.graphsage import Detector
from ml.training.runtime import train_stage1, calibrate, train_stage2, load, Predictor, negative_pairs, known_relationships
from ml.smoke import fixtures
from ml.contracts import export_schemas


def manifest(start=120, end=300):
    return {"schema_version": VERSION, "run_id": "test", "session_id": "test", "source": "mininet",
            "start": start, "end": end, "normal": True, "capture_complete": True, "replay_speed": 1,
            "inventory": [{"device_id": "a", "device_type": "hub", "addresses": [{"ip": "10.0.0.11", "start": start, "end": end}]},
                          {"device_id": "b", "device_type": "light", "addresses": [{"ip": "10.0.0.12", "start": start, "end": end}]},
                          {"device_id": "c", "device_type": "camera", "addresses": [{"ip": "10.0.0.13", "start": start, "end": end}]}]}


def record(window=120, uid="one", **kwargs):
    return {"schema_version": VERSION, "window_start": window, "uid": uid,
            "orig_h": "10.0.0.11", "resp_h": "10.0.0.12", "orig_p": 40000, "resp_p": 8080,
            "flow_start": 121, "proto": "tcp", "orig_ip_bytes": 120, "resp_ip_bytes": 300,
            "orig_pkts": 2, "resp_pkts": 3, "observed_duration": 2, "established": True, "failed": False,
            "new_flow": window == 120, **kwargs}


def test_directionality_and_long_flow_deltas():
    graphs = list(build_snapshots([record(), record(180, orig_ip_bytes=40, resp_ip_bytes=80)], manifest()))
    a, b, c = graphs[0]["nodes"]
    assert a["features"][:4] == [120, 300, 2, 3]
    assert b["features"][:4] == [300, 120, 3, 2]
    assert c["active"] is False
    assert graphs[1]["nodes"][0]["features"][:2] == [40, 80]
    assert graphs[1]["nodes"][0]["features"][5] == 0  # ongoing, not a new flow
    assert graphs[0]["nodes"][0]["features"][8] == 1
    assert graphs[1]["nodes"][0]["features"][8] == 0
    assert len(graphs[0]["edges"]) == 1
    assert graphs[2]["edges"] == []


def test_silence_is_not_outage():
    m = manifest()
    m["outages"] = [{"device_id": "a", "start": 180, "end": 240}]
    graphs = list(build_snapshots([], m))
    assert graphs[0]["nodes"][0]["available"]
    assert not graphs[1]["nodes"][0]["available"]
    assert graphs[1]["nodes"][1]["available"]
    assert not any(graphs[1]["nodes"][0]["feature_mask"])


def test_order_duplicates_and_future_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        list(build_snapshots([record(), record()], manifest()))
    with pytest.raises(ValueError, match="sorted|predates"):
        list(build_snapshots([record(180), record()], manifest()))
    with pytest.raises(ValueError, match="Future"):
        list(build_snapshots([record(flow_start=999)], manifest()))


def test_icmp_not_port_and_unknown_outcome_not_failure():
    v, mask, _ = features([(record(proto="icmp", resp_p=0), True)], set())
    assert v[9] == 0 and not mask[14]
    v, mask, _ = features([(record(established=False), True)], set())
    assert not mask[14]
    v, mask, _ = features([(record(established=False, failed=True), True)], set())
    assert v[14] == 1 and mask[14]


def test_label_roles_and_mixed_windows():
    m = manifest()
    m["normal"] = False
    label = {"device_id": "a", "start": 130, "end": 250, "label": 1, "role": "victim",
             "attack_family": "scan", "onset": "later", "evidence": "test"}
    with pytest.raises(ValueError, match="Victim"):
        validate_labels([label], m)
    label["role"] = "actor"
    validate_labels([label], m)
    assert label_window([label], "a", 120)[0] == -1
    assert label_window([label], "a", 180)[0] == 1
    assert label_window([label], "b", 180)[0] == -1


def test_schemas_match_real_objects(tmp_path):
    export_schemas(tmp_path)
    m = manifest()
    g = next(build_snapshots([record()], m))
    for name, obj in (("manifest", m), ("telemetry", record()), ("graph", g)):
        validate(obj, read_json(tmp_path / f"{name}.schema.json"))


def test_normalizer_train_only_unknown_and_empty_graph(tmp_path):
    catalog = fixtures(tmp_path)
    train = load_partition(catalog, "stage1_train")
    scaler = Normalizer().fit(train, min_type_rows=1)
    before = copy.deepcopy(scaler.state)
    g = copy.deepcopy(train[0])
    g["nodes"][0]["features"][0] = 1e12
    g["nodes"][0]["device_type"] = "unknown"
    g["edges"] = []
    data = to_pyg(g, scaler)
    assert scaler.state == before
    assert data.edge_index.shape == (2, 0)
    assert data.x.shape[1] == 50
    for architecture in ("sage", "gcn", "mlp"):
        assert torch.isfinite(Detector(architecture).encode(data.x, data.edge_index)).all()
    with pytest.raises(ValueError, match="clean"):
        Normalizer().fit(load_partition(catalog, "stage2_val"))


def test_query_edge_removal_and_graph_batch_isolation(tmp_path):
    catalog = fixtures(tmp_path)
    gs = load_partition(catalog, "stage1_train")
    scaler = Normalizer().fit(gs)
    d = to_pyg(gs[0], scaler)
    model = Detector().eval()
    pair = torch.tensor([[0], [1]])
    without = d.edge_index[:, ~(((d.edge_index[0] == 0) & (d.edge_index[1] == 1)) |
                                ((d.edge_index[0] == 1) & (d.edge_index[1] == 0)))]
    assert torch.allclose(model.score_pairs(d.x, d.edge_index, pair), model.score_pairs(d.x, without, pair))
    pairs = torch.tensor([[0, 2], [1, 3]])
    together = model.score_pairs(d.x, d.edge_index, pairs)
    separate = torch.cat([model.score_pairs(d.x, d.edge_index, pairs[:, i:i+1]) for i in range(2)])
    assert torch.allclose(together, separate, atol=1e-6)
    known = known_relationships(gs)
    negative = negative_pairs(gs[0], known, random.Random(0)).t().tolist()
    assert all(i != j and (i, j) not in ((0, 1), (1, 0), (2, 3), (3, 2)) for i, j in negative)


def test_history_free_classifier(tmp_path):
    catalog = fixtures(tmp_path)
    gs = load_partition(catalog, "stage1_train")
    d = to_pyg(gs[0], Normalizer().fit(gs))
    model = Detector().eval()
    before = model.compromised_logits(d.x, d.edge_index)
    d.x[:, HISTORY_FEATURE] = 1000
    d.x[:, MASK_OFFSET + HISTORY_FEATURE] = 1
    assert torch.equal(before, model.compromised_logits(d.x, d.edge_index))


def test_end_to_end_freeze_and_checkpoint(tmp_path):
    catalog = fixtures(tmp_path / "data")
    a, b, c = (tmp_path / f"{name}.pt" for name in ("a", "b", "c"))
    train_stage1(catalog, a, epochs=2, smoke=True)
    calibrate(catalog, a, b)
    first, _, _ = load(b)
    train_stage2(catalog, b, c, epochs=2)
    second, _, _ = load(c)
    for name, p in first.named_parameters():
        if not name.startswith("classifier."):
            assert torch.equal(p, dict(second.named_parameters())[name])
    predictor = Predictor(c)
    g = load_partition(catalog, "stage2_test")[0]
    one = predictor.predict(g)
    assert one == Predictor(c).predict(g)
    assert all(0 <= d["compromised_probability"] <= 1 for d in one["devices"])
    assert one["smoke_model"]
    assert not readiness(catalog)["ready"]
    clean_catalog = read_json(catalog)
    clean_catalog["smoke"] = False
    clean_catalog["partitions"]["stage2_train"] = []
    clean_catalog["partitions"]["stage2_val"] = []
    clean_catalog["partitions"]["stage2_test"] = []
    write_json(tmp_path / "data" / "prepared" / "normal-only-catalog.json", clean_catalog)
    assert readiness(tmp_path / "data" / "prepared" / "normal-only-catalog.json", stage1_only=True)["ready"]
    with pytest.raises(ValueError, match="Smoke"):
        train_stage1(catalog, tmp_path / "bad.pt", epochs=1)


def test_catalog_rejects_overlap_and_mutated_files(tmp_path):
    catalog = fixtures(tmp_path)
    config = read_json(tmp_path / "sources.json")
    config["sources"][0]["partitions"][1]["start"] -= 60
    (tmp_path / "bad.json").write_text(json.dumps(config))
    with pytest.raises(ValueError, match="overlap"):
        prepare(tmp_path / "bad.json", tmp_path / "bad")
    first = read_json(catalog)["partitions"]["stage1_train"][0]
    path = catalog.parent / first["path"]
    with path.open("a") as h:
        h.write("\n")
    with pytest.raises(ValueError, match="changed"):
        load_partition(catalog, "stage1_train")


def test_accelerated_capture_rejected():
    m = manifest()
    m["replay_speed"] = 3600
    with pytest.raises(ValueError, match="Accelerated"):
        validate_manifest(m, training=True)

"""Evaluate frozen A/B heads on separately prepared, held-out labeled sessions."""
from collections import Counter, defaultdict
from pathlib import Path
import json
import math
import time

import numpy as np
import torch
from sklearn.metrics import average_precision_score, roc_auc_score

from ml.schema import SCHEMA_HASH, VERSION, FEATURES, TYPES, file_hash, read_json, read_jsonl, require, write_json, write_jsonl
from ml.training.runtime import Predictor

SIGNALS = {"head_a": ("reconstruction_error", "reconstruction_flag"),
           "head_b": ("link_anomaly", "link_flag")}


def checked_test_graphs(catalog_path, training_catalog, artifact):
    catalog_path, training_catalog = Path(catalog_path).resolve(), Path(training_catalog).resolve()
    require(file_hash(training_catalog) == artifact["catalog_sha256"], "Training catalog does not match checkpoint provenance")
    training, external = read_json(training_catalog), read_json(catalog_path)
    require(not external.get("smoke") or artifact.get("smoke"), "Smoke captures cannot evaluate a production checkpoint")
    protected_runs = {r["run_id"] for name in ("stage1_train", "stage1_val", "calibration", "stage2_train", "stage2_val")
                      for r in training["partitions"].get(name, [])}
    protected_sources = [s for s in training["sources"] if s["run_id"] in protected_runs]
    protected_sessions = {s["session_id"] for s in protected_sources}
    protected_hashes = {h for s in protected_sources for h in
                        [s.get("telemetry_sha256"), s.get("graph_sha256"), *s.get("capture_hashes", [])] if h}
    sources = {s["run_id"]: s for s in external["sources"]}
    require(len(sources) == len(external["sources"]), "Duplicate source identities")
    test_rules = external["partitions"].get("stage2_test", [])
    require(test_rules, "No held-out stage2_test runs")
    external_fitting_sessions = {sources[r["run_id"]]["session_id"] for name in ("stage2_train", "stage2_val")
                                 for r in external["partitions"].get(name, [])}
    graphs, provenance, seen_runs, seen_snapshots, seen_hashes = [], [], set(), set(), set()
    for rule in test_rules:
        run_id = rule["run_id"]
        require(run_id in sources and run_id not in seen_runs, "Unknown or duplicate test run")
        seen_runs.add(run_id)
        source = sources[run_id]
        require(run_id not in protected_runs and source["session_id"] not in protected_sessions,
                "Test session overlaps checkpoint fitting data")
        require(source["session_id"] not in external_fitting_sessions, "External test session overlaps matrix train/validation")
        hashes = {h for h in [source.get("telemetry_sha256"), source.get("graph_sha256"), *source.get("capture_hashes", [])] if h}
        require(not hashes & protected_hashes, "Test capture/telemetry/graphs reused from checkpoint fitting data")
        require(not hashes & seen_hashes, "Duplicate test captures or graph sources")
        seen_hashes.update(hashes)
        require(not source.get("smoke") or artifact.get("smoke"), "Smoke test source")
        path = (catalog_path.parent / rule["path"]).resolve()
        require(path.is_relative_to(catalog_path.parent), "Graph path must stay within prepared directory")
        require(file_hash(path) == source["graph_sha256"], "Test graph file changed after preparation")
        require(rule["start"] % 60 == rule["end"] % 60 == 0 and rule["end"] > rule["start"], "Invalid test bounds")
        selected = []
        for g in read_jsonl(path):
            if not rule["start"] <= g["window_start"] < rule["end"]:
                continue
            require(g.get("schema_version") == VERSION and g.get("schema_hash") == SCHEMA_HASH and g.get("window_seconds") == 60,
                    "Test graph schema incompatible with checkpoint")
            require(g["run_id"] == run_id and g["session_id"] == source["session_id"] and g["source"] == source["source"], "Graph identity/provenance mismatch")
            require(g["window_start"] == rule["start"] + len(selected) * 60, "Missing, repeated or unordered test windows")
            key = (run_id, g["window_start"])
            require(key not in seen_snapshots, "Duplicate test snapshot")
            seen_snapshots.add(key)
            require(len({n["device_id"] for n in g["nodes"]}) == len(g["nodes"]), "Duplicate device nodes")
            for n in g["nodes"]:
                require(n["device_type"] in TYPES and n["label"] in (-1, 0, 1), "Invalid node type or label")
                require(len(n["features"]) == len(n["feature_mask"]) == len(FEATURES) and all(math.isfinite(v) for v in n["features"]), "Invalid feature vector")
                require(not g["normal"] or n["label"] != 1, "Positive label in normal control")
                if n["label"] == 1:
                    info = n.get("label_details") or {}
                    require(info.get("role") == "actor" and info.get("attack_family") and info.get("onset") in ("from_start", "later"), "Positive label lacks actor/interval evidence")
                    require(info.get("start") is not None and info["start"] <= g["window_start"], "Invalid positive onset")
            for e in g["edges"]:
                require(0 <= e["source"] < len(g["nodes"]) and 0 <= e["target"] < len(g["nodes"]) and e["source"] != e["target"], "Invalid graph edge")
            selected.append(g)
        require(len(selected) == (rule["end"] - rule["start"]) // 60, "Incomplete test graph coverage")
        graphs.extend(selected)
        provenance.append({k: source.get(k) for k in ("run_id", "session_id", "source", "graph_sha256", "telemetry_sha256", "manifest_sha256", "labels_sha256", "capture_hashes", "synthetic")})
    labels = {n["label"] for g in graphs for n in g["nodes"] if n["active"] and n["available"] and n["label"] >= 0}
    require(labels == {0, 1}, "External evaluation requires active normal and malicious actors")
    return graphs, provenance


def metrics(rows, signal, flag):
    population = [r for r in rows if r["status"] == "ok" and r["label"] in (0, 1)]
    eligible = [r for r in population if r[signal] is not None]
    population_positives = sum(r["label"] == 1 for r in population)
    result = {"population": len(population), "population_positives": population_positives,
              "support": len(eligible), "unscored": len(population) - len(eligible),
              "coverage": len(eligible) / len(population) if population else None}
    if not eligible:
        return result
    y = np.array([r["label"] for r in eligible], dtype=bool)
    pred = np.array([r[flag] for r in eligible], dtype=bool)
    scores = np.array([r[signal] for r in eligible])
    require(np.isfinite(scores).all(), "Nonfinite evaluation scores")
    tp, fp, tn, fn = (int(v.sum()) for v in (y & pred, ~y & pred, ~y & ~pred, y & ~pred))
    both = y.any() and (~y).any()
    result.update(positives=int(y.sum()), true_positive=tp, false_positive=fp, true_negative=tn, false_negative=fn,
                  accuracy=(tp+tn)/len(y), balanced_accuracy=((tp/(tp+fn))+(tn/(tn+fp)))/2 if both else None,
                  precision=tp/(tp+fp) if tp+fp else None, recall=tp/(tp+fn) if tp+fn else None,
                  f1=2*tp/(2*tp+fp+fn) if y.any() else None,
                  false_positive_rate=fp/(fp+tn) if fp+tn else None,
                  population_recall=tp/population_positives if population_positives else None,
                  population_f1=2*tp/(tp+fp+population_positives) if population_positives else None,
                  pr_auc=float(average_precision_score(y,scores)) if both else None,
                  roc_auc=float(roc_auc_score(y,scores)) if both else None)
    return result


def evaluate_external_ab(catalog, training_catalog, checkpoint, out, device="cuda"):
    out = Path(out)
    require(not out.exists(), "Choose a new evaluation report path")
    started = time.perf_counter()
    checkpoint_hash = file_hash(checkpoint)
    predictor = Predictor(checkpoint, device=device)
    graphs, provenance = checked_test_graphs(catalog, training_catalog, predictor.artifact)
    contexts = {}
    actors = defaultdict(set)
    session_roles = defaultdict(set)
    for g in graphs:
        session_roles[g["session_id"]].add("control" if g["normal"] else "attack")
        for n in g["nodes"]:
            if n["label"] == 1:
                d = n["label_details"]
                context = (d["attack_family"], d["onset"])
                require(g["session_id"] not in contexts or contexts[g["session_id"]] == context, "Conflicting scenario labels")
                contexts[g["session_id"]] = context
                actors[g["session_id"]].add(n["device_id"])
    require(all(roles == {"attack", "control"} for roles in session_roles.values()), "Each test session must have an attack and matched control")
    require(set(contexts) == set(session_roles), "Session lacks verified malicious actor labels")
    print(json.dumps({"event":"evaluation_start","graphs":len(graphs),"runs":len(provenance),"sessions":len(contexts),"device":str(next(predictor.model.parameters()).device)}),flush=True)
    rows, episodes, detected = [], {}, defaultdict(list)
    frozen_metadata = json.dumps({k: predictor.artifact[k] for k in ("normalizer", "thresholds")},sort_keys=True)
    for index, g in enumerate(graphs, 1):
        prediction = predictor.predict(g)
        family, onset = contexts[g["session_id"]]
        for n,p in zip(g["nodes"],prediction["devices"]):
            row = {**p,"run_id":g["run_id"],"session_id":g["session_id"],"window_start":g["window_start"],
                   "label":n["label"],"behavior_label":n.get("behavior_label",n["label"]),"relationship_label":n.get("relationship_label",n["label"]),"source":g["source"],"attack_family":family,"onset":onset,
                   "run_role":"control" if g["normal"] else "attack","counterpart_actor":n["device_id"] in actors[g["session_id"]]}
            rows.append(row)
            if n["label"] == 1:
                start = n["label_details"]["start"]
                for head,(_,flag) in SIGNALS.items():
                    key = (g["run_id"], n["device_id"], start, head)
                    if row['behavior_label' if head=='head_a' else 'relationship_label'] != 1: continue
                    episodes[key] = {"run_id":g["run_id"],"device_id":n["device_id"],"attack_start":start,"head":head,"attack_family":family,"onset":onset}
                    if p[flag]: detected[key].append(g["window_start"]+60-start)
        if index % 120 == 0:
            print(json.dumps({"event":"evaluation_progress","graphs_done":index,"graphs_total":len(graphs),"elapsed_seconds":time.perf_counter()-started}),flush=True)
    require(file_hash(checkpoint) == checkpoint_hash, "Checkpoint changed during evaluation")
    require(json.dumps({k: predictor.artifact[k] for k in ("normalizer","thresholds")},sort_keys=True) == frozen_metadata, "Scaler or thresholds changed during evaluation")
    summarize = lambda subset: {head:metrics([{**r,"label":r["behavior_label" if head=="head_a" else "relationship_label"]} for r in subset],signal,flag) for head,(signal,flag) in SIGNALS.items()}
    report = {"label_semantics":{"head_a":"behavioral anomaly including observed affected victims","head_b":"unexpected initiated relationships","actor_label":"compromised actor for Head C"},"partition":"stage2_test","checkpoint_sha256":checkpoint_hash,"training_catalog_sha256":file_hash(training_catalog),
              "evaluation_catalog_sha256":file_hash(catalog),"checkpoint_unchanged":True,"thresholds_and_scaler_unchanged":True,
              "device":str(next(predictor.model.parameters()).device),"synthetic":read_json(catalog).get("synthetic",False),
              "architecture_revision":predictor.model.revision,"link_score_scope":"initiated_relationships" if predictor.model.revision=="robust" else "incident_relationships",
              "head_c_trained":predictor.artifact.get("classifier_trained",False),"graphs":len(graphs),"runs":len(provenance),
              "paired_sessions":len(contexts),"compromised_actor_diagnostic":{head:metrics(rows,signal,flag) for head,(signal,flag) in SIGNALS.items()},"overall":summarize(rows),"matched_actors":summarize([r for r in rows if r["counterpart_actor"]]),
              "groups":{},"source_provenance":provenance,
              "limitations":["Metrics describe simulated network behaviors on known actor/device types",
                             "Graph files are hash-verified; capture/telemetry hashes are compared for reuse, but remote raw source files are not independently verified",
                             "Head B metrics are conditional on available initiated relationships; unscored windows are reported explicitly"]}
    for field in ("attack_family","onset","device_type","source","run_role"):
        report["groups"][field]={v:summarize([r for r in rows if r[field]==v]) for v in sorted({r[field] for r in rows})}
    report["matched_actor_groups"]={family:summarize([r for r in rows if r["counterpart_actor"] and r["attack_family"]==family]) for family in sorted({r["attack_family"] for r in rows})}
    report["latency"]=[{**info,"seconds_to_window_decision":min(detected[key]) if detected[key] else None} for key,info in episodes.items()]
    report["episode_summary"]={}
    for head in SIGNALS:
        values=[e["seconds_to_window_decision"] for e in report["latency"] if e["head"]==head]
        found=[v for v in values if v is not None]
        report["episode_summary"][head]={"attack_episodes":len(values),"detected":len(found),"missed":len(values)-len(found),
                                         "detection_rate":len(found)/len(values) if values else None,
                                         "median_detected_latency_seconds":float(np.median(found)) if found else None}
    report["elapsed_seconds"]=time.perf_counter()-started
    write_json(out,report)
    write_jsonl(out.with_suffix('.predictions.jsonl'),rows)
    print(json.dumps({"event":"evaluation_complete","report":str(out),"elapsed_seconds":report["elapsed_seconds"],"overall":report["overall"],"episode_summary":report["episode_summary"]}),flush=True)
    return report

"""Synthetic fixture generation for software validation, NEVER training evidence."""
import random
from pathlib import Path
from ml.schema import VERSION, write_json, write_jsonl
from ml.dataset_prep.catalog import prepare


def fixtures(out):
    out = Path(out).resolve()
    sources = []
    rng = random.Random(5)
    for run, windows, attack, part in (("clean", 80, False, None), ("attack-train", 20, True, "stage2_train"),
                                     ("attack-val", 20, True, "stage2_val"), ("attack-test", 20, True, "stage2_test")):
        start = 1800000000
        end = start + windows * 60
        inventory = [{"device_id": f"d{i}", "device_type": typ, "addresses": [{"ip": f"10.0.0.{i+11}", "start": start, "end": end}]}
                     for i, typ in enumerate(("hub", "light", "camera", "plug"))]
        m = {"schema_version": VERSION, "run_id": run, "session_id": run, "source": "mininet", "normal": not attack,
             "start": start, "end": end, "inventory": inventory, "capture_complete": True, "replay_speed": 1, "smoke": True}
        rows = []
        for w in range(windows):
            t = start + w * 60
            for i, j in ((0, 1), (2, 3)):
                bad = attack and i == 0
                packets = rng.randint(100, 300) if bad else rng.randint(2, 8)
                rows.append({"schema_version": VERSION, "window_start": t, "uid": f"{run}-{w}-{i}",
                    "orig_h": f"10.0.0.{i+11}", "resp_h": f"10.0.0.{j+11}", "orig_p": 45000 + w, "resp_p": 8080,
                    "proto": "tcp", "flow_start": t + 1, "orig_ip_bytes": packets * (1000 if bad else 64),
                    "resp_ip_bytes": 0 if bad else packets * 100, "orig_pkts": packets, "resp_pkts": 0 if bad else packets,
                    "observed_duration": rng.uniform(0.1, 5), "new_flow": True, "established": not bad, "failed": bad})
        labels = [{"device_id": f"d{i}", "start": start, "end": end, "label": int(attack and i == 0),
                   "role": "actor" if attack and i == 0 else "normal", "evidence": "synthetic-software-test",
                   "attack_family": "synthetic", "onset": "from_start"} for i in range(4)]
        write_json(out / run / "manifest.json", m)
        write_jsonl(out / run / "telemetry.jsonl", rows)
        write_jsonl(out / run / "labels.jsonl", labels)
        rules = [{"name": part, "start": start, "end": end}] if part else [
            {"name": p, "start": start + a * 60, "end": start + b * 60} for p, a, b in
            (("stage1_train", 0, 40), ("stage1_val", 40, 50), ("calibration", 50, 60), ("normal_test", 60, 80), ("stage2_train", 0, 40))]
        sources.append({"manifest": f"{run}/manifest.json", "telemetry": f"{run}/telemetry.jsonl", "labels": f"{run}/labels.jsonl", "partitions": rules})
    write_json(out / "sources.json", {"sources": sources, "smoke": True})
    prepare(out / "sources.json", out / "prepared")
    return out / "prepared" / "catalog.json"


def run(out, epochs=3):
    from ml.training.runtime import train_stage1, calibrate, train_stage2, evaluate
    out = Path(out)
    catalog = fixtures(out)
    train_stage1(catalog, out / "stage1.pt", epochs=epochs, smoke=True)
    calibrate(catalog, out / "stage1.pt", out / "calibrated.pt")
    train_stage2(catalog, out / "calibrated.pt", out / "model.pt", epochs=epochs)
    return evaluate(catalog, out / "model.pt", out / "evaluation.json")

import copy
import math
import random
from collections import defaultdict
from pathlib import Path
import importlib.metadata

import numpy as np
import torch
from torch.nn import functional as F

from ml.schema import (SCHEMA_HASH, VERSION, HISTORY_FEATURE, MASK_OFFSET,
                       write_json, read_json, require, file_hash)
from ml.dataset_prep.catalog import load_partition
from ml.dataset_prep.tensors import Normalizer, to_pyg
from ml.model.graphsage import Detector, reconstruction_errors


def seed_everything(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    # Small household graphs run faster without a large BLAS thread pool.
    torch.set_num_threads(1)


def checkpoint(model, scaler, **metadata):
    return {"schema_version": VERSION, "schema_hash": SCHEMA_HASH, "model_config": model.config,
            "model_state": model.state_dict(), "normalizer": scaler.state,
            "dependencies": {p: importlib.metadata.version(p) for p in ("torch", "torch_geometric", "numpy")},
            **metadata}


def save(path, artifact):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(artifact, path)


def load(path):
    artifact = torch.load(path, map_location="cpu", weights_only=True)
    require(artifact["schema_hash"] == SCHEMA_HASH, "Checkpoint feature schema mismatch")
    model = Detector(**artifact["model_config"])
    model.load_state_dict(artifact["model_state"])
    model.eval()
    return model, Normalizer(artifact["normalizer"]), artifact


def known_relationships(graphs):
    result = set()
    for g in graphs:
        ids = [n["device_id"] for n in g["nodes"]]
        for e in g["edges"]:
            result.add((ids[e["source"]], ids[e["target"]]))
            result.add((ids[e["target"]], ids[e["source"]]))
    return result


def negative_pairs(graph, known, rng):
    ids = [n["device_id"] for n in graph["nodes"]]
    observed = {(e["source"], e["target"]) for e in graph["edges"]}
    candidates = [(i, j) for i in range(len(ids)) for j in range(len(ids)) if i != j
                  and graph["nodes"][i]["available"] and graph["nodes"][j]["available"]
                  and (i, j) not in observed and (j, i) not in observed
                  and (ids[i], ids[j]) not in known]
    rng.shuffle(candidates)
    chosen = candidates[:len(observed)]
    return torch.tensor(chosen, dtype=torch.long).t().contiguous() if chosen else torch.empty((2, 0), dtype=torch.long)


def stage1_loss(model, graph, data, known, rng, augment=False):
    x = data.x
    if augment:
        x = x.clone()
        mask = torch.rand(len(x)) < 0.1
        x[mask, HISTORY_FEATURE] = 0
        x[mask, MASK_OFFSET + HISTORY_FEATURE] = 0
    predicted = model.decoder(model.encode(x, data.edge_index))
    valid = data.feature_mask * data.available[:, None]
    rec = ((predicted - data.target).square() * valid).sum() / valid.sum().clamp(min=1)
    negative = negative_pairs(graph, known, rng)
    # Without both classes there is no meaningful link-discrimination update.
    if negative.shape[1] and data.positive_pairs.shape[1]:
        pairs = torch.cat([data.positive_pairs, negative], dim=1)
        y = torch.cat([torch.ones(data.positive_pairs.shape[1]), torch.zeros(negative.shape[1])])
        logits = model.score_pairs(x, data.edge_index, pairs)
        # Equal class contribution even when there are too few unique negatives.
        losses = F.binary_cross_entropy_with_logits(logits, y, reduction="none")
        link = (losses[y == 1].mean() + losses[y == 0].mean()) / 2
        return rec, link, True
    return rec, rec * 0, False


def validation_loss(model, graphs, tensors, known):
    rec, link = [], []
    rng = random.Random(0)
    model.eval()
    with torch.no_grad():
        for g, d in zip(graphs, tensors):
            a, b, has_link = stage1_loss(model, g, d, known, rng)
            rec.append(float(a))
            if has_link:
                link.append(float(b))
    return {"reconstruction": float(np.mean(rec)), "link": float(np.mean(link)) if link else None}


def train_stage1(catalog, out, epochs=100, patience=10, seed=42, architecture="sage", batch_size=32,
                 learning_rate=0.001, smoke=False):
    seed_everything(seed)
    require(not read_json(catalog).get("smoke") or smoke, "Smoke catalog cannot train a production checkpoint")
    train, val = (load_partition(catalog, p) for p in ("stage1_train", "stage1_val"))
    require(train and val, "Stage 1 needs separate training and validation partitions")
    require(all(g["normal"] and g["source"] in ("mininet", "virtual_testbed") for g in train + val),
            "Stage 1 requires clean testbed graphs")
    require(all(n["label"] != 1 for g in train + val for n in g["nodes"]), "Attack label in Stage 1")
    scaler = Normalizer().fit(train)
    tensors = [to_pyg(g, scaler) for g in train]
    validation = [to_pyg(g, scaler) for g in val]
    model = Detector(architecture=architecture)
    known = known_relationships(train)
    initial = validation_loss(model, val, validation, known)
    require(initial["link"] is not None, "No validation edges with valid negative candidates")
    optimizer = torch.optim.Adam([p for n, p in model.named_parameters() if not n.startswith("classifier.")], lr=learning_rate)
    rng = random.Random(seed)
    history = []
    best, bad, state = float("inf"), 0, None
    for epoch in range(epochs):
        model.train()
        indices = list(range(len(train)))
        rng.shuffle(indices)
        for offset in range(0, len(indices), batch_size):
            optimizer.zero_grad()
            batch = indices[offset:offset + batch_size]
            for i in batch:
                a, b, _ = stage1_loss(model, train[i], tensors[i], known, rng, augment=True)
                ((a + b) / len(batch)).backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5)
            optimizer.step()
        metrics = validation_loss(model, val, validation, known)
        require(all(math.isfinite(v) for v in metrics.values() if v is not None), "Nonfinite validation loss")
        score = metrics["reconstruction"] + metrics["link"]
        history.append({"epoch": epoch + 1, **metrics})
        if score < best - 1e-5:
            best, bad, state = score, 0, copy.deepcopy(model.state_dict())
        else:
            bad += 1
        if bad >= patience:
            break
    require(state is not None, "No training epochs completed")
    model.load_state_dict(state)
    final = validation_loss(model, val, validation, known)
    # Compare reconstruction with the training per-type mean predictor (zero in scaled space).
    baseline = float(np.mean([float((d.target.square() * d.feature_mask).sum() / d.feature_mask.sum().clamp(min=1)) for d in validation]))
    passed = final["reconstruction"] < baseline and final["link"] < math.log(2)
    gate = {"passed": passed, "reconstruction_mean_baseline": baseline, "initial": initial, "final": final,
            "reason": "Requires lower held-out reconstruction error than the mean predictor and balanced link BCE below log(2)."}
    artifact = checkpoint(model, scaler, stage=1, classifier_trained=False, quality_gate=gate, smoke=smoke,
                          synthetic_training=read_json(catalog).get("synthetic", False),
                          history=history, catalog_sha256=file_hash(catalog), seed=seed,
                          settings={"epochs": epochs, "patience": patience, "batch_size": batch_size, "learning_rate": learning_rate})
    save(out, artifact)
    write_json(str(out) + ".report.json", {"quality_gate": gate, "history": history})
    require(passed or smoke, f"Stage-1 quality gate failed; diagnostic checkpoint saved to {out}. Inspect data/losses before calibration.")
    return gate


@torch.no_grad()
def raw_scores(model, scaler, graph):
    data = to_pyg(graph, scaler)
    rec = reconstruction_errors(model, data).tolist()
    probs = torch.sigmoid(model.score_pairs(data.x, data.edge_index, data.positive_pairs)).tolist()
    incident = defaultdict(list)
    for (u, v), p in zip(data.positive_pairs.t().tolist(), probs):
        incident[u].append(p)
        incident[v].append(p)
    return data, rec, {i: 1 - min(ps) for i, ps in incident.items()}, probs


def calibrate(catalog, source, out, percentile=99, minimum_type=500):
    require(0 < percentile < 100, "Percentile must lie in (0,100)")
    model, scaler, artifact = load(source)
    require(artifact["quality_gate"]["passed"] or artifact.get("smoke"), "Stage 1 did not pass validation")
    require(file_hash(catalog) == artifact["catalog_sha256"], "Calibration must use the Stage-1 split catalog")
    graphs = load_partition(catalog, "calibration")
    require(graphs and all(g["normal"] for g in graphs), "Calibration requires a separate normal-only partition")
    by_type = {"reconstruction": defaultdict(list), "link_anomaly": defaultdict(list)}
    for g in graphs:
        _, rec, link, _ = raw_scores(model, scaler, g)
        for i, n in enumerate(g["nodes"]):
            if not (n["available"] and n["active"]):
                continue
            for signal, value in (("reconstruction", rec[i]), ("link_anomaly", link.get(i))):
                if value is not None:
                    by_type[signal]["global"].append(value)
                    by_type[signal][n["device_type"]].append(value)
    thresholds = {}
    for signal, groups in by_type.items():
        require(groups["global"], f"No normal calibration observations for {signal}")
        thresholds[signal] = {t: {"value": float(np.percentile(v, percentile)), "count": len(v)}
                              for t, v in groups.items() if t == "global" or len(v) >= minimum_type}
    artifact["thresholds"] = thresholds
    artifact["calibration"] = {"percentile": percentile, "minimum_type": minimum_type}
    save(out, artifact)
    return thresholds


def embedding_examples(model, scaler, graphs):
    xs, ys, keys = [], [], []
    for g in graphs:
        d = to_pyg(g, scaler)
        valid = d.available & d.active & (d.y >= 0)
        with torch.no_grad():
            h = model.encode(model.head_c_input(d.x), d.edge_index)
        xs.append(h[valid])
        ys.append(d.y[valid])
        keys.extend((g["source"], int(n["label"])) for n in g["nodes"] if n["available"] and n["active"] and n["label"] >= 0)
    require(xs, "Empty labeled partition")
    x, y = torch.cat(xs), torch.cat(ys)
    require(len(y) > 0 and set(y.tolist()) == {0.0, 1.0}, "Head C needs active, known examples of BOTH classes")
    return x, y, keys


def train_stage2(catalog, source, out, epochs=100, patience=10, seed=42, batch_size=32, learning_rate=0.001):
    seed_everything(seed)
    model, scaler, artifact = load(source)
    require(artifact.get("thresholds"), "Calibrate Heads A/B before Stage 2")
    require(file_hash(catalog) == artifact["catalog_sha256"], "Use one predeclared catalog for both training stages")
    model.freeze_base()
    before = {n: p.detach().clone() for n, p in model.named_parameters() if not n.startswith("classifier.")}
    train, val = (load_partition(catalog, p) for p in ("stage2_train", "stage2_val"))
    x, y, keys = embedding_examples(model, scaler, train)
    vx, vy, _ = embedding_examples(model, scaler, val)
    from collections import Counter
    counts = Counter(keys)
    weights = torch.tensor([1 / counts[k] for k in keys], dtype=torch.float32)
    weights /= weights.mean()
    optimizer = torch.optim.Adam(model.classifier.parameters(), lr=learning_rate)
    history, best, bad, state = [], float("inf"), 0, None
    for epoch in range(epochs):
        order = torch.randperm(len(y))
        model.classifier.train()
        for batch in order.split(batch_size):
            optimizer.zero_grad()
            loss = F.binary_cross_entropy_with_logits(model.classifier(x[batch]).flatten(), y[batch], reduction="none")
            (loss * weights[batch]).mean().backward()
            optimizer.step()
        model.eval()
        with torch.no_grad():
            loss = float(F.binary_cross_entropy_with_logits(model.classifier(vx).flatten(), vy))
        require(math.isfinite(loss), "Nonfinite classifier validation loss")
        history.append({"epoch": epoch + 1, "validation_bce": loss})
        if loss < best - 1e-5:
            best, bad, state = loss, 0, copy.deepcopy(model.classifier.state_dict())
        else:
            bad += 1
        if bad >= patience:
            break
    require(state is not None, "No classifier training epochs completed")
    model.classifier.load_state_dict(state)
    require(all(torch.equal(p, before[n]) for n, p in model.named_parameters() if n in before), "Frozen base changed")
    with torch.no_grad():
        logits = model.classifier(vx).flatten().detach()
    # Temperature fitting uses validation data only. Scalar bounded to avoid numerical overflow.
    log_temperature = torch.zeros((), requires_grad=True)
    temp_optimizer = torch.optim.LBFGS([log_temperature], max_iter=50)
    def closure():
        temp_optimizer.zero_grad()
        temperature = log_temperature.clamp(-4, 4).exp()
        loss = F.binary_cross_entropy_with_logits(logits / temperature, vy)
        loss.backward()
        return loss
    temp_optimizer.step(closure)
    temperature = float(log_temperature.detach().clamp(-4, 4).exp())
    probs = torch.sigmoid(logits / temperature).numpy()
    from sklearn.metrics import precision_recall_curve
    precision, recall, candidates = precision_recall_curve(vy.numpy(), probs)
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    threshold = float(candidates[int(np.argmax(f1))])
    artifact.update(model_state=model.state_dict(), stage=2, classifier_trained=True,
                    classifier_temperature=temperature, classifier_threshold=threshold,
                    classifier_history=history, classifier_seed=seed,
                    classifier_source_counts={f"{s}:{label}": n for (s, label), n in counts.items()})
    save(out, artifact)
    write_json(str(out) + ".report.json", {"history": history, "temperature": temperature, "threshold": threshold,
                                           "source_class_counts": artifact["classifier_source_counts"], "base_unchanged": True})
    return {"validation_bce": best, "classifier_threshold": threshold, "base_unchanged": True}


class Predictor:
    def __init__(self, checkpoint_path):
        self.model, self.scaler, self.artifact = load(checkpoint_path)
        require(self.artifact.get("thresholds"), "Checkpoint has no calibrated thresholds")
        self.model_id = file_hash(checkpoint_path)[:16]

    def threshold(self, signal, typ):
        stats = self.artifact["thresholds"][signal]
        return stats.get(typ, stats["global"])["value"]

    @torch.no_grad()
    def predict(self, graph):
        data, rec, link, edge_probs = raw_scores(self.model, self.scaler, graph)
        c = None
        if self.artifact["classifier_trained"]:
            c = torch.sigmoid(self.model.compromised_logits(data.x, data.edge_index) /
                              self.artifact["classifier_temperature"]).tolist()
        results = []
        for i, n in enumerate(graph["nodes"]):
            valid = n["available"] and n["active"]
            a, b, cp = (rec[i], link.get(i), c[i] if c else None) if valid else (None, None, None)
            results.append({"device_id": n["device_id"], "device_type": n["device_type"],
                            "status": "ok" if valid else "inactive" if n["available"] else "unavailable",
                            "reconstruction_error": a, "link_anomaly": b,
                            "link_expectedness": 1 - b if b is not None else None,
                            "compromised_probability": cp,
                            "reconstruction_flag": a > self.threshold("reconstruction", n["device_type"]) if a is not None else None,
                            "link_flag": b > self.threshold("link_anomaly", n["device_type"]) if b is not None else None,
                            "classifier_flag": cp >= self.artifact["classifier_threshold"] if cp is not None else None})
        return {"schema_version": VERSION, "schema_hash": SCHEMA_HASH, "model_id": self.model_id,
                "run_id": graph["run_id"], "window_start": graph["window_start"],
                "smoke_model": self.artifact.get("smoke", False),
                "synthetic_training_model": self.artifact.get("synthetic_training", False), "devices": results,
                "edges": [{"source": g["source"], "target": g["target"], "expectedness": p}
                          for g, p in zip(sorted(graph["edges"], key=lambda e: (e["source"], e["target"])), edge_probs)]}


def binary_metrics(rows, signal, flag):
    from sklearn.metrics import average_precision_score, precision_score, recall_score, roc_auc_score
    eligible = [r for r in rows if r[signal] is not None and r["label"] in (0, 1)]
    if not eligible:
        return {"support": 0}
    y = np.array([r["label"] for r in eligible])
    scores = np.array([r[signal] for r in eligible])
    pred = np.array([r[flag] for r in eligible], dtype=bool)
    both = len(set(y)) == 2
    return {"support": len(y), "positives": int(y.sum()),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "false_positive_rate": float(pred[y == 0].mean()) if (y == 0).any() else None,
            "pr_auc": float(average_precision_score(y, scores)) if both else None,
            "roc_auc": float(roc_auc_score(y, scores)) if both else None}


def evaluate(catalog, source, out, partition="stage2_test"):
    predictor = Predictor(source)
    require(file_hash(catalog) == predictor.artifact["catalog_sha256"], "Evaluation catalog changed after training")
    rows, detections, episode_starts = [], defaultdict(list), {}
    for g in load_partition(catalog, partition):
        predictions = predictor.predict(g)
        for n, p in zip(g["nodes"], predictions["devices"]):
            info = n.get("label_details") or {}
            row = {**p, "label": n["label"], "source": g["source"],
                   "onset": info.get("onset") or "normal", "attack_family": info.get("attack_family") or "normal"}
            rows.append(row)
            if n["label"] == 1 and info.get("start") is not None:
                for flag in ("reconstruction_flag", "link_flag", "classifier_flag"):
                    key = (g["run_id"], n["device_id"], info["start"], flag)
                    episode_starts[key] = info["start"]
                    if p[flag]:
                        detections[key].append(g["window_start"] + 60 - info["start"])
    signals = (("reconstruction_error", "reconstruction_flag"), ("link_anomaly", "link_flag"),
               ("compromised_probability", "classifier_flag"))
    report = {"partition": partition, "overall": {s: binary_metrics(rows, s, f) for s, f in signals}, "groups": {}}
    for group in ("device_type", "attack_family", "source", "onset"):
        report["groups"][group] = {v: {s: binary_metrics([r for r in rows if r[group] == v], s, f) for s, f in signals}
                                    for v in sorted({r[group] for r in rows})}
    report["latency"] = [{"run_id": k[0], "device_id": k[1], "attack_start": k[2], "signal": k[3],
                           "seconds_to_window_decision": min(detections[k]) if detections[k] else None}
                          for k in episode_starts]
    write_json(out, report)
    return report

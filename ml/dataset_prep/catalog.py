"""Explicit split manifests; no random split of correlated device windows."""
from pathlib import Path
from collections import defaultdict

from ml.schema import read_json, read_jsonl, write_json, write_jsonl, validate_manifest, file_hash, require
from ml.graph.build import build_snapshots

PARTITIONS = ("stage1_train", "stage1_val", "calibration", "normal_test", "stage2_train", "stage2_val", "stage2_test")


def prepare(config_path, out):
    config_path, out = Path(config_path).resolve(), Path(out).resolve()
    config = read_json(config_path)
    sources = config["sources"]
    hashes = set()
    capture_hashes = set()
    sessions = defaultdict(set)
    catalog = {"schema_revision": 2, "calibration_mode": config.get("calibration_mode", "pooled"), "protocol": config.get("protocol", {}), "partitions": {p: [] for p in PARTITIONS}, "sources": [], "smoke": False, "synthetic": False}
    for entry in sources:
        base = config_path.parent
        manifest_path = (base / entry["manifest"]).resolve()
        manifest = validate_manifest(read_json(manifest_path), training=True)
        telemetry = (base / entry["telemetry"]).resolve()
        digest = file_hash(telemetry)
        require(digest not in hashes, "Duplicate telemetry source; declare multiple partitions on one entry instead")
        hashes.add(digest)
        declared_hashes = set(manifest.get("capture_hashes", []))
        if manifest.get("pcap_sha256"):
            declared_hashes.add(manifest["pcap_sha256"])
        require(not (capture_hashes & declared_hashes), "The same raw capture is used by multiple source entries")
        capture_hashes.update(declared_hashes)
        catalog["smoke"] |= manifest.get("smoke", False)
        catalog["synthetic"] |= manifest.get("synthetic", False)
        labels = list(read_jsonl(base / entry["labels"])) if entry.get("labels") else []
        run = manifest["run_id"]
        require(run not in {s["run_id"] for s in catalog["sources"]}, "Duplicate run_id")
        rules = entry["partitions"]
        for rule in rules:
            require(rule["name"] in PARTITIONS, "Unknown partition")
            require(manifest["start"] <= rule["start"] < rule["end"] <= manifest["end"], "Partition outside capture")
            require(rule["start"] % 60 == rule["end"] % 60 == 0, "Partition boundaries must align to minutes")
            if rule["name"] in PARTITIONS[:4]:
                require(manifest["normal"] and manifest["source"] in ("mininet", "virtual_testbed"),
                        "Stage 1 requires clean testbed data")
            if rule["name"].startswith("stage2"):
                sessions[manifest["session_id"]].add(rule["name"])
        # A normal training window can also be a Head C negative training example.
        # Other overlaps across partitions are leakage.
        for i, a in enumerate(rules):
            for b in rules[i + 1:]:
                if a["start"] < b["end"] and b["start"] < a["end"]:
                    require({a["name"], b["name"]} == {"stage1_train", "stage2_train"}, "Partition overlap leaks data")
        target = out / f"{len(catalog['sources']):03d}-graphs.jsonl"
        # The capture may contain startup or final teardown outside declared study bounds.
        # Those complete telemetry rows are retained in the source but not in study graphs.
        cropped = (r for r in read_jsonl(telemetry) if manifest["start"] <= r["window_start"] < manifest["end"])
        write_jsonl(target, build_snapshots(cropped, manifest, labels))
        item = {"run_id": run, "session_id": manifest["session_id"], "source": manifest["source"],
                "manifest": str(manifest_path), "telemetry_sha256": digest,
                "capture_hashes": sorted(declared_hashes), "smoke": manifest.get("smoke", False),
                "synthetic": manifest.get("synthetic", False),
                "manifest_sha256": file_hash(manifest_path), "graph_sha256": file_hash(target),
                "normal_context": entry.get("normal_context", "background"),
                "labels_sha256": file_hash(base / entry["labels"]) if entry.get("labels") else None}
        catalog["sources"].append(item)
        for rule in rules:
            catalog["partitions"][rule["name"]].append({"path": target.name, "start": rule["start"], "end": rule["end"],
                                                        "run_id": run})
    require(all(len(v) == 1 for v in sessions.values()), "Head C session appears in multiple splits")
    # Chronology is checked within a run, preserving distinct independent scenario sessions.
    for src in catalog["sources"]:
        ordered = []
        for partition in PARTITIONS[:4]:
            ordered.extend((p["start"], p["end"], PARTITIONS.index(partition))
                           for p in catalog["partitions"][partition] if p["run_id"] == src["run_id"])
        require([p[2] for p in sorted(ordered)] == sorted(p[2] for p in ordered), "Stage-1 splits must be chronological")
    write_json(out / "catalog.json", catalog)
    return catalog


def load_partition(catalog_path, name):
    catalog_path = Path(catalog_path)
    catalog = read_json(catalog_path)
    result = []
    for rule in catalog["partitions"][name]:
        path = catalog_path.parent / rule["path"]
        source = next(s for s in catalog["sources"] if s["run_id"] == rule["run_id"])
        require(file_hash(path) == source["graph_sha256"], "Graph file changed after preparation")
        result.extend({**g, "normal_context": source.get("normal_context", "background")} for g in read_jsonl(path) if rule["start"] <= g["window_start"] < rule["end"])
    return result


def readiness(catalog_path, stage1_only=False):
    report = {"synthetic": read_json(catalog_path).get("synthetic", False), "partitions": {}, "errors": [], "warnings": []}
    if read_json(catalog_path).get("smoke"):
        report["errors"].append("Synthetic/smoke data is not a production training corpus")
    if read_json(catalog_path).get("synthetic"):
        report["warnings"].append("Virtual-clock packets are simulated; validate on independent real captures before deployment")
    for name in (PARTITIONS[:4] if stage1_only else PARTITIONS):
        graphs = load_partition(catalog_path, name)
        nodes = [n for g in graphs for n in g["nodes"] if n["available"] and n["active"]]
        counts = {str(label): sum(n["label"] == label for n in nodes) for label in (-1, 0, 1)}
        report["partitions"][name] = {"graphs": len(graphs), "active_nodes": len(nodes), "labels": counts,
                                          "edges": sum(len(g["edges"]) for g in graphs)}
        if not graphs:
            report["errors"].append(f"Missing {name}")
        elif not nodes:
            report["errors"].append(f"No active available devices in {name}; check sensor and identity mapping")
        if name.startswith("stage2") and (not counts["0"] or not counts["1"]):
            report["errors"].append(f"{name} requires known active normal AND malicious actors")
        if name == "calibration" and len(nodes) < 1000:
            report["warnings"].append("Fewer than 1000 active calibration observations; tail estimates are weak")
    report["ready"] = not report["errors"]
    return report

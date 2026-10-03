"""Create explicit training split configuration from completed collection runs."""
from pathlib import Path
from ml.schema import read_json, write_json, require


def normal_source(normal_run):
    normal_run = Path(normal_run).resolve()
    manifest = read_json(normal_run / "manifest.json")
    start, end = manifest["start"], manifest["end"]
    require(end - start >= 7 * 86400, "Default normal split requires seven days")
    rules = []
    for name, a, b in (("stage1_train", 0, 4), ("stage1_val", 4, 5), ("calibration", 5, 6), ("normal_test", 6, 7), ("stage2_train", 0, 4)):
        rules.append({"name": name, "start": start + a * 86400, "end": start + b * 86400})
    return {"manifest": str(normal_run / "manifest.json"), "telemetry": str(normal_run / "zeek" / "telemetry.jsonl"),
            "labels": str(normal_run / "labels.jsonl"), "partitions": rules}


def make_normal_config(normal_run, out):
    write_json(out, {"sources": [normal_source(normal_run)]})
    return {"sources": 1, "config": str(out)}


def make_config(normal_run, matrix, runs_root, out):
    sources = [normal_source(normal_run)]
    matrix = Path(matrix).resolve()
    for run in read_json(matrix)["runs"]:
        plan = read_json(matrix.parent / run["plan"])
        directory = Path(runs_root).resolve() / plan["run_id"]
        m = read_json(directory / "manifest.json")
        sources.append({"manifest": str(directory / "manifest.json"), "telemetry": str(directory / "zeek" / "telemetry.jsonl"),
                        "labels": str(directory / "labels.jsonl"),
                        "partitions": [{"name": run["partition"], "start": m["start"], "end": m["end"]}]})
    write_json(out, {"sources": sources})
    return {"sources": len(sources), "config": str(out)}

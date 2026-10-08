"""Run `python -m ml --help` from the repository root."""
import argparse
import json
from pathlib import Path

from ml.schema import read_json, read_jsonl, write_json, write_jsonl


def main():
    p = argparse.ArgumentParser(description="AutoMUD database-free graph learning")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("schemas"); s.add_argument("--out", default="configs/gnn/schemas")
    s = sub.add_parser("audit-datasets")
    for arg in ("cic", "unsw-normal", "unsw-attack", "out"):
        s.add_argument("--" + arg, required=True)
    s.add_argument("--topology", default="network/testbed/topology.json")
    s = sub.add_parser("unsw-attack-identities"); s.add_argument("--workbook", required=True)
    s.add_argument("--out", required=True); s.add_argument("--existing", default="configs/gnn/unsw-identities.json")
    s = sub.add_parser("extract"); s.add_argument("--pcap", nargs="+", required=True); s.add_argument("--out", required=True); s.add_argument("--zeek", default="zeek")
    s = sub.add_parser("prepare"); s.add_argument("--config", required=True); s.add_argument("--out", required=True)
    s = sub.add_parser("readiness"); s.add_argument("--catalog", required=True); s.add_argument("--out")
    s.add_argument("--stage1-only", action="store_true")
    s = sub.add_parser("calibrate-traffic"); s.add_argument("--sources", required=True); s.add_argument("--out", required=True)
    s = sub.add_parser("public-manifest")
    for arg in ("telemetry", "identities", "source", "run-id", "out"):
        s.add_argument("--" + arg, required=True)
    s.add_argument("--normal", action="store_true")
    s = sub.add_parser("inspect-capture")
    s.add_argument("--manifest", required=True); s.add_argument("--telemetry", required=True)
    s.add_argument("--out", required=True); s.add_argument("--reference")
    s = sub.add_parser("plan-normal"); s.add_argument("--topology", default="network/testbed/topology.json"); s.add_argument("--profiles"); s.add_argument("--days", type=float, default=7); s.add_argument("--seed", type=int, default=42); s.add_argument("--out", required=True)
    s = sub.add_parser("plan-attacks"); s.add_argument("--topology", default="network/testbed/topology.json"); s.add_argument("--profiles"); s.add_argument("--out", required=True)
    s = sub.add_parser("make-config")
    for arg in ("normal-run", "matrix", "runs-root", "out"):
        s.add_argument("--" + arg, required=True)
    s = sub.add_parser("make-normal-config")
    for arg in ("normal-run", "out"):
        s.add_argument("--" + arg, required=True)
    for command in ("train-stage1", "train-stage2", "train-all"):
        s = sub.add_parser(command)
        s.add_argument("--catalog", required=True); s.add_argument("--out", required=True)
        s.add_argument("--epochs", type=int, default=100); s.add_argument("--patience", type=int, default=10)
        s.add_argument("--seed", type=int, default=42); s.add_argument("--batch-size", type=int, default=32)
        s.add_argument("--learning-rate", type=float, default=0.001)
        s.add_argument("--device", default="auto", help="auto, cpu, cuda, or cuda:0")
        if command == "train-stage2":
            s.add_argument("--checkpoint", required=True)
        else:
            s.add_argument("--architecture", choices=("sage", "gcn", "mlp"), default="sage")
            s.add_argument("--revision", choices=("legacy", "robust"), default="legacy")
    s = sub.add_parser("calibrate"); s.add_argument("--device", default="auto"); s.add_argument("--catalog", required=True); s.add_argument("--checkpoint", required=True); s.add_argument("--out", required=True); s.add_argument("--percentile", type=float, default=99)
    s = sub.add_parser("evaluate"); s.add_argument("--device", default="auto"); s.add_argument("--catalog", required=True); s.add_argument("--checkpoint", required=True); s.add_argument("--out", required=True); s.add_argument("--partition", choices=("normal_test", "stage2_test"), default="stage2_test")
    s = sub.add_parser("predict"); s.add_argument("--checkpoint", required=True); s.add_argument("--graphs", required=True); s.add_argument("--out", required=True)
    s = sub.add_parser("smoke"); s.add_argument("--out", required=True); s.add_argument("--epochs", type=int, default=3)
    args = p.parse_args()
    result = None
    if args.command == "schemas":
        from ml.contracts import export_schemas
        export_schemas(args.out)
        result = {"schemas": args.out}
    elif args.command == "audit-datasets":
        from ml.dataset_prep.inventory import audit
        audit(args.cic, args.unsw_normal, args.unsw_attack, args.topology, args.out)
        result = {"report": args.out}
    elif args.command == "unsw-attack-identities":
        from ml.dataset_prep.inventory import unsw_attack_identities
        result = unsw_attack_identities(args.workbook, args.out, args.existing)
    elif args.command == "extract":
        from ml.dataset_prep.extract import extract
        result = {"telemetry": extract(args.pcap, args.out, args.zeek)}
    elif args.command == "prepare":
        from ml.dataset_prep.catalog import prepare
        prepare(args.config, args.out)
        result = {"catalog": str(Path(args.out) / "catalog.json")}
    elif args.command == "readiness":
        from ml.dataset_prep.catalog import readiness
        result = readiness(args.catalog, stage1_only=args.stage1_only)
        if args.out:
            write_json(args.out, result)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["ready"] else 2)
    elif args.command == "calibrate-traffic":
        from ml.dataset_prep.traffic_profiles import calibrate_traffic
        source_path = Path(args.sources).resolve()
        sources = read_json(source_path)["sources"]
        for source in sources:
            for k in ("manifest", "telemetry"):
                source[k] = str(source_path.parent / source[k])
        profiles = calibrate_traffic(sources, args.out)
        result = {"devices": len(profiles["devices"]), "profiles": args.out}
    elif args.command == "public-manifest":
        from ml.dataset_prep.public_manifest import make_manifest
        result = make_manifest(args.telemetry, args.identities, args.source, args.run_id, args.out, args.normal)
    elif args.command == "inspect-capture":
        from ml.dataset_prep.quality import inspect_capture
        report = inspect_capture(args.manifest, args.telemetry, args.out, args.reference)
        result = {"report": args.out, "warnings": report["warnings"]}
    elif args.command == "plan-normal":
        from network.testbed.collection_plan import build_plan
        plan = build_plan(read_json(args.topology), round(args.days * 86400), args.seed, read_json(args.profiles) if args.profiles else None)
        if args.profiles:
            from ml.schema import file_hash
            plan["profiles_file"] = str(Path(args.profiles).resolve())
            plan["profiles_sha256"] = file_hash(args.profiles)
        write_json(args.out, plan)
        result = {"events": len(plan["events"]), "calibrated": plan["calibrated"]}
    elif args.command == "plan-attacks":
        from network.testbed.collection_plan import write_matrix
        result = {"plans": len(write_matrix(args.topology, args.out, args.profiles))}
    elif args.command == "make-config":
        from ml.dataset_prep.configure import make_config
        result = make_config(args.normal_run, args.matrix, args.runs_root, args.out)
    elif args.command == "make-normal-config":
        from ml.dataset_prep.configure import make_normal_config
        result = make_normal_config(args.normal_run, args.out)
    elif args.command.startswith("train-"):
        from ml.training.runtime import train_stage1, train_stage2, calibrate, evaluate
        kw = dict(epochs=args.epochs, patience=args.patience, seed=args.seed, batch_size=args.batch_size, learning_rate=args.learning_rate, device=args.device)
        if args.command == "train-stage1":
            result = train_stage1(args.catalog, args.out, architecture=args.architecture, revision=args.revision, **kw)
        elif args.command == "train-stage2":
            result = train_stage2(args.catalog, args.checkpoint, args.out, **kw)
        else:
            from ml.dataset_prep.catalog import readiness
            from ml.schema import require
            report = readiness(args.catalog)
            require(report["ready"], "Dataset not ready: " + "; ".join(report["errors"]))
            out = Path(args.out)
            train_stage1(args.catalog, out / "stage1.pt", architecture=args.architecture, revision=args.revision, **kw)
            calibrate(args.catalog, out / "stage1.pt", out / "calibrated.pt", device=args.device)
            train_stage2(args.catalog, out / "calibrated.pt", out / "model.pt", **kw)
            evaluate(args.catalog, out / "model.pt", out / "normal-test.json", "normal_test", device=args.device)
            evaluate(args.catalog, out / "model.pt", out / "attack-test.json", device=args.device)
            result = {"model": str(out / "model.pt")}
    elif args.command == "calibrate":
        from ml.training.runtime import calibrate
        result = calibrate(args.catalog, args.checkpoint, args.out, args.percentile, device=args.device)
    elif args.command == "evaluate":
        from ml.training.runtime import evaluate
        result = evaluate(args.catalog, args.checkpoint, args.out, args.partition, device=args.device)
    elif args.command == "predict":
        from ml.training.runtime import Predictor
        predictor = Predictor(args.checkpoint)
        write_jsonl(args.out, (predictor.predict(g) for g in read_jsonl(args.graphs)))
        result = {"predictions": args.out}
    elif args.command == "smoke":
        from ml.smoke import run
        result = run(args.out, args.epochs)
    if result is not None:
        print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()

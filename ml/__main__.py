"""Inference and canonical extraction CLI for the selected teammate GNN package."""
import argparse
import json
from pathlib import Path
from ml.schema import read_json, read_jsonl, write_jsonl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    load = commands.add_parser('check-model', help='Verify hashes and load the frozen models without scoring')
    load.add_argument('--bundle', default='models/gnn')
    load.add_argument('--device', default='cpu')
    load.add_argument('--allow-candidate', action='store_true')
    fixture = commands.add_parser('check-fixture', help='Check loading and outputs against the consumed reference fixture')
    fixture.add_argument('--bundle', default='models/gnn')
    fixture.add_argument('--fixture', default='fixtures/gnn')
    fixture.add_argument('--device', default='cpu')
    predict = commands.add_parser('predict', help='Score already-prepared v4 graphs; no fitting')
    predict.add_argument('--bundle', default='models/gnn')
    predict.add_argument('--device', default='cpu')
    predict.add_argument('--graphs', required=True)
    predict.add_argument('--out', required=True)
    build = commands.add_parser('build-graphs', help='Convert canonical telemetry and inventory manifest to v4 graphs')
    build.add_argument('--telemetry', required=True)
    build.add_argument('--manifest', required=True)
    build.add_argument('--out', required=True)
    extract = commands.add_parser('extract', help='Extract canonical telemetry from PCAPs with the project Zeek policy')
    extract.add_argument('--pcap', nargs='+', required=True)
    extract.add_argument('--out', required=True)
    extract.add_argument('--zeek', default='zeek')
    service = commands.add_parser('serve', help='Run the stateful live GNN HTTP service')
    service.add_argument('--config', default='configs/gnn/live/service.json')
    export = commands.add_parser('export-bundle', help='Package a trained compatible checkpoint without fitting')
    export.add_argument('--checkpoint', required=True)
    export.add_argument('--frozen-b', default='models/gnn/frozen-b.pt')
    export.add_argument('--out', required=True)
    export.add_argument('--version', required=True)
    export.add_argument('--results')
    sample = commands.add_parser('sample-window', help='Write explicitly labeled engineering API example, not captured traffic')
    sample.add_argument('--out', required=True)
    submit = commands.add_parser('submit-window', help='Send one completed canonical window to the running service')
    submit.add_argument('--request', required=True)
    submit.add_argument('--url', default='http://127.0.0.1:8001')
    submit.add_argument('--token-env', default='AUTOMUD_GNN_API_TOKEN')
    submit.add_argument('--out')
    acceptance = commands.add_parser('validate-live-capture', help='Verify real lab capture -> Zeek -> live API feature parity and swapping')
    acceptance.add_argument('--capture-dir', required=True)
    acceptance.add_argument('--out', required=True)
    acceptance.add_argument('--zeek', default='/opt/zeek/bin/zeek')
    bench = commands.add_parser('benchmark-live', help='Measure API/CPU throughput on synthetic engineering traffic')
    bench.add_argument('--out', required=True)
    bench.add_argument('--windows', type=int, default=60)
    bench.add_argument('--devices', type=int, default=12)
    args = parser.parse_args()
    if args.command == 'benchmark-live':
        from ml.live.benchmark import benchmark
        print(json.dumps(benchmark(args.out, args.windows, args.devices), indent=2))
    elif args.command == 'validate-live-capture':
        from ml.live.acceptance import validate_capture
        print(json.dumps(validate_capture(args.capture_dir, args.out, args.zeek), indent=2))
    elif args.command == 'sample-window':
        import time
        from ml.live.examples import example_window
        from ml.schema import write_json
        if Path(args.out).exists():
            parser.error('Output already exists; choose a new path')
        write_json(args.out, example_window(int(time.time() // 60) * 60 - 60))
    elif args.command == 'submit-window':
        import os
        from ml.live.client import Client
        if args.out and Path(args.out).exists():
            parser.error('Output already exists; choose a new path')
        result = Client(args.url, os.environ.get(args.token_env)).submit(read_json(args.request))
        if args.out:
            from ml.schema import write_json
            write_json(args.out, result)
        else:
            print(json.dumps(result, indent=2))
    elif args.command == 'serve':
        from ml.live.server import serve
        serve(args.config)
    elif args.command == 'export-bundle':
        from ml.live.bundles import export_bundle
        print(json.dumps(export_bundle(args.checkpoint, args.frozen_b, args.out, args.version, args.results), indent=2))
    elif args.command == 'check-fixture':
        from ml.verify_fixture import verify_fixture
        print(json.dumps(verify_fixture(args.bundle, args.fixture, args.device), indent=2))
    elif args.command in ('check-model', 'predict'):
        from ml.inference import GNNBundle
        model = GNNBundle(args.bundle, args.device, allow_candidate=getattr(args, 'allow_candidate', False))
        if args.command == 'predict':
            out = Path(args.out)
            if out.exists():
                parser.error('Output already exists; choose a new path')
            write_jsonl(out, (model.score_graph(g) for g in read_jsonl(args.graphs)))
        model.verify_inputs()
        print(json.dumps(dict(status='ok', verified_files=len(model.inputs), command=args.command)))
    elif args.command == 'build-graphs':
        from ml.ab_targets.graphs import build_v4
        if Path(args.out).exists():
            parser.error('Output already exists; choose a new path')
        write_jsonl(args.out, build_v4(read_jsonl(args.telemetry), read_json(args.manifest)))
    else:
        from ml.dataset_prep.extract import extract
        print(extract(args.pcap, args.out, args.zeek))


if __name__ == '__main__':
    main()

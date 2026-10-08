"""Train, calibrate, and evaluate Heads A/B with a durable run log."""
import argparse
import json
from pathlib import Path
import sys
import time
import traceback
import os

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.schema import write_json
from ml.dataset_prep.catalog import readiness
from ml.training.runtime import train_stage1, calibrate, evaluate, resolve_training_device


class Tee:
    def __init__(self, console, logfile):
        self.console, self.logfile = console, logfile

    def write(self, text):
        self.console.write(text)
        self.logfile.write(text)
        self.logfile.flush()

    def flush(self):
        self.console.flush()
        self.logfile.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--device', default='cuda')
    parser.add_argument('--epochs', type=int, default=100)
    parser.add_argument('--patience', type=int, default=10)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--revision', choices=('legacy','robust'), default='legacy')
    args = parser.parse_args()
    out = Path(args.out).resolve()
    if out.exists():
        raise ValueError('Use a new run directory to preserve existing results')
    resolve_training_device(args.device)
    report = readiness(args.catalog, stage1_only=True)
    if not report['ready']:
        raise ValueError('Dataset not ready: ' + '; '.join(report['errors']))
    out.mkdir(parents=True)
    write_json(out/'readiness.json', report)
    started = time.perf_counter()
    original = sys.stdout
    with (out/'training.log').open('w', encoding='utf-8') as logfile:
        sys.stdout = Tee(original, logfile)
        try:
            write_json(out/'run-status.json', {'pid':os.getpid(),'started_at':time.time(),'status':'training','device':args.device,'catalog':str(Path(args.catalog).resolve()),'epochs':args.epochs,'patience':args.patience})
            gate = train_stage1(args.catalog, out/'stage1.pt', epochs=args.epochs, patience=args.patience, seed=args.seed, device=args.device, revision=args.revision)
            write_json(out/'run-status.json', {'status':'calibrating','device':args.device})
            thresholds = calibrate(args.catalog, out/'stage1.pt', out/'calibrated.pt', device=args.device)
            write_json(out/'run-status.json', {'status':'evaluating','device':args.device})
            evaluation = evaluate(args.catalog, out/'calibrated.pt', out/'normal-test.json', partition='normal_test', device=args.device)
            summary = {'status':'complete','device':args.device,'elapsed_seconds':time.perf_counter()-started,
                       'quality_gate':gate,'thresholds':thresholds,'normal_test':evaluation['overall'],
                       'checkpoint':str(out/'calibrated.pt'),'synthetic_data':bool(report.get('synthetic', False)),'classifier_trained':False}
            write_json(out/'run-status.json', summary)
            print(json.dumps(summary),flush=True)
        except Exception as exc:
            write_json(out/'run-status.json', {'status':'failed','error':str(exc),'elapsed_seconds':time.perf_counter()-started})
            traceback.print_exc(file=sys.stdout)
            raise
        finally:
            sys.stdout = original


if __name__ == '__main__':
    main()

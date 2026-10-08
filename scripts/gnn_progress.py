"""Read collection/training progress without importing torch or modifying a run."""
import argparse
import json
from pathlib import Path
import os
import time


def read(path):
    try: return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except (OSError, ValueError): return {}


def snapshot(run):
    run = Path(run)
    status = read(run/'pipeline-status.json') or read(run/'run-status.json')
    training = Path(status.get('training_directory',run))
    training_status = read(training/'run-status.json')
    progress = read(training/'stage1.pt.progress.json')
    result = {'run':str(run), **status, 'training':training_status, 'epoch_progress':progress}
    pid = status.get('pid') or training_status.get('pid')
    if pid and os.name == 'posix':
        try: os.kill(int(pid),0); result['process_alive']=True
        except PermissionError: result['process_alive']=None
        except ProcessLookupError: result['process_alive']=False
        if result.get('process_alive') is False and status.get('status') not in ('complete','failed'):
            result['warning']='Process is no longer running; inspect pipeline.log for an interruption.'
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',default='data/gnn/local-v2-run')
    p.add_argument('--watch',action='store_true')
    p.add_argument('--json',action='store_true')
    a=p.parse_args()
    while True:
        result=snapshot(a.run)
        if a.json: print(json.dumps(result,indent=2),flush=True)
        else:
            s=result.get('status','not started'); progress=result['epoch_progress']
            print(f"Status: {s}; phase: {result.get('phase',result['training'].get('status','unknown'))}")
            if 'completed_runs' in result: print(f"Captures: {result['completed_runs']}/{result['total_runs']}")
            if s=='running' and result.get('phase')=='capture_and_extract' and 'eta_capture_seconds' in result:
                print(f"Estimated remaining capture/extraction time: {result['eta_capture_seconds']/60:.1f} minutes; training follows")
            if result.get('started_at'):
                elapsed=result.get('elapsed_seconds',time.time()-result['started_at'])
                print(f"Elapsed: {elapsed/60:.1f} minutes")
            if progress.get('event')=='training_complete':
                print(f"Training finished: {progress['epochs_completed']} epochs; GPU: {progress.get('gpu_name')}")
            if 'epoch' in progress:
                print(f"Epoch: {progress['epoch']}/{progress['max_epochs']}; GPU: {progress.get('gpu_name')}")
                print(f"ETA to epoch limit: {progress.get('eta_max_seconds',0)/60:.1f} minutes (early stopping may finish sooner)")
                print(f"Validation reconstruction: {progress['reconstruction']:.6f}; link: {progress['link']:.6f}")
            if result.get('error'): print('Error:',result['error'])
            if result.get('warning'): print(result['warning'])
            if s=='complete': print('Finished. Results:',result.get('evaluation_report',result['training'].get('checkpoint')))
            print('Run:',result['run'],flush=True)
        if not a.watch or result.get('status') in ('complete','failed'): break
        time.sleep(10)


if __name__=='__main__': main()

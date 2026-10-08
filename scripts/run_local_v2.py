"""Reproducible local A/B development run; reports synthetic and real results separately."""
import argparse
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ml.schema import read_json, read_jsonl, write_json, file_hash, require, SCHEMA_HASH
from ml.dataset_prep.catalog import prepare, load_partition
from ml.dataset_prep.extract import extract
from network.testbed.collection_plan import build_plan, FAMILIES
from network.testbed.virtual_capture import render
from scripts.collect_gnn_matrix import virtual_start


def capture_and_extract(plan_path, directory, start):
    began=time.perf_counter()
    plan_path,directory=Path(plan_path),Path(directory)
    if not (directory/'manifest.json').exists(): render(plan_path,directory,start)
    m=read_json(directory/'manifest.json')
    require(m['capture_complete'] and m['plan_sha256']==file_hash(plan_path) and m['pcap_sha256']==file_hash(directory/'capture.pcap'),'Capture provenance mismatch')
    if not (directory/'zeek/telemetry.jsonl').exists(): extract([directory/'capture.pcap'],directory/'zeek',zeek='/opt/zeek/bin/zeek')
    else:
        extraction=read_json(directory/'zeek/extraction.json')
        require(extraction['policy_sha256']==file_hash('network/zeek/automud-window.zeek'),'Cached extraction policy differs')
        require(extraction['inputs'][0]['sha256']==m['pcap_sha256'],'Cached extraction capture differs')
    return m,time.perf_counter()-began


def pipeline(root, epochs):
    root=Path(root).resolve(); root.mkdir(parents=True,exist_ok=True)
    require(os.name=="posix", "Run this pipeline inside the dedicated Linux distribution")
    import fcntl
    lock=(root/'.pipeline.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    status={'status':'running','phase':'planning','pid':os.getpid(),'started_at':time.time(),
            'schema_hash':SCHEMA_HASH,'training_directory':str(root/'model'),
            'test_seeds':[29,31],'development_seeds':[11,13,17,19],
            'completed_runs':0,'total_runs':192}
    def update(**fields):
        status.update(fields,updated_at=time.time()); write_json(root/'pipeline-status.json',status)
    update()
    try:
        topology=read_json('network/testbed/topology.json'); profiles=read_json('data/gnn/generator-profiles.json')
        actors=[next(d for d in topology['devices'] if d.startswith(prefix)) for prefix in ('SamsungCamera_','SamsungSmartThings_','BelkinWemoSwitch_')]
        sources=[]; capture_times=[]; pairs={}
        # Keep the existing seven-day raw normal corpus, rebuilt with the new causal schema.
        normal=Path('data/collection/virtual-normal').resolve()
        manifest=read_json(normal/'manifest.json'); t=manifest['start']
        rules=[{'name':p,'start':t+a*86400,'end':t+b*86400} for p,a,b in
               [('stage1_train',0,4),('stage1_val',4,5),('calibration',5,6),('normal_test',6,7)]]
        sources.append({'manifest':str(normal/'manifest.json'),'telemetry':str(normal/'zeek/telemetry.jsonl'),
                        'normal_context':'background','partitions':rules})
        jobs=[]
        for seed in [11,13,17,19,29,31]:
            controls=(True,) if seed in [11,13,17,19] else (False,True)
            for family,actor,onset,control in itertools.product(FAMILIES,actors,('from_start','later'),controls):
                plan=build_plan(topology,1200,seed,profiles,family,actor,onset,control)
                plan['profiles_file']=str(Path('data/gnn/generator-profiles.json').resolve())
                plan['profiles_sha256']=file_hash(plan['profiles_file'])
                plan_path=root/'plans'/(plan['run_id']+'.json'); directory=root/'captures'/plan['run_id']
                if plan_path.exists(): require(read_json(plan_path)==plan,'Existing plan differs; use a new run directory')
                else: write_json(plan_path,plan)
                part='stage1_train' if seed in [11,13,17] else ('stage1_val' if onset=='from_start' else 'calibration') if seed==19 else 'stage2_test'
                jobs.append((plan_path,directory,virtual_start(1704067200,plan['session_id']),part))
        update(phase='capture_and_extract',workers=3)
        with ProcessPoolExecutor(max_workers=3) as pool:
            futures={pool.submit(capture_and_extract,p,d,t):(d,part) for p,d,t,part in jobs}
            for future in as_completed(futures):
                directory,part=futures[future]; m,seconds=future.result()
                sources.append({'manifest':str(directory/'manifest.json'),'telemetry':str(directory/'zeek/telemetry.jsonl'),
                    'labels':str(directory/'labels.jsonl'),'normal_context':'legitimate_burst_cold_start',
                    'partitions':[{'name':part,'start':m['start'],'end':m['end']}]})
                capture_times.append(seconds)
                update(completed_runs=status['completed_runs']+1,current_run=m['run_id'],
                       eta_capture_seconds=sum(capture_times[-9:])/len(capture_times[-9:])*(192-status['completed_runs']-1)/3)
        sources.sort(key=lambda s:s['manifest'])
        update(phase='prepare')
        write_json(root/'sources.json',{'sources':sources,'calibration_mode':'stratified_normal_contexts',
            'protocol':{'training':'clean background + controls seeds 11/13/17','validation':'seed 19 from_start controls',
                        'calibration':'seed 19 later controls','test':'all seed 29/31 attack-control pairs',
                        'schema':'v2','test_access':'no threshold fitting or architecture selection on test'}})
        catalog=root/'prepared/catalog.json'
        if not catalog.exists(): prepare(root/'sources.json',root/'prepared')
        # Development observability audit only: fresh test is not read before model freeze.
        controls_graphs=load_partition(catalog,'stage1_train')
        write_json(root/'development-coverage.json',{'normal_training_graphs':len(controls_graphs),
            'active_device_windows':sum(n['active'] and n['available'] for g in controls_graphs for n in g['nodes']),
            'external_service_edges':sum(g['nodes'][e['target']]['device_type']=='external_service' for g in controls_graphs for e in g['edges']),
            'note':'Coverage counts do not prove independent examples or detection performance.'})
        update(phase='train')
        model=root/'model'
        if not (model/'calibrated.pt').exists():
            subprocess.run([sys.executable,'-u','scripts/train_ab.py','--catalog',str(catalog),'--out',str(model),
                            '--revision','robust','--device','cuda','--epochs',str(epochs),'--patience','10'],check=True)
        update(phase='evaluate_frozen_test')
        report=root/'evaluation.json'
        if not report.exists():
            subprocess.run([sys.executable,'-u','scripts/evaluate_ab.py','--catalog',str(catalog),
                '--training-catalog',str(catalog),'--checkpoint',str(model/'calibrated.pt'),'--out',str(report),'--device','cuda'],check=True)
        update(status='complete',phase='complete',evaluation_report=str(report),elapsed_seconds=time.time()-status['started_at'])
    except Exception as e:
        update(status='failed',error=str(e),elapsed_seconds=time.time()-status['started_at'])
        traceback.print_exc(); raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',default='data/gnn/local-v2-run'); p.add_argument('--epochs',type=int,default=100)
    a=p.parse_args(); pipeline(a.out,a.epochs)

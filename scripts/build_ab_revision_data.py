"""Build normal-only revision data and fresh virtual attack/control holdouts."""
import argparse
import copy
from pathlib import Path
import shutil
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ml.schema import read_json,read_jsonl,write_json,file_hash,require
from ml.dataset_prep.catalog import PARTITIONS
from network.testbed.collection_plan import build_plan,FAMILIES
from network.testbed.virtual_capture import render
from scripts.collect_gnn_matrix import virtual_start


def training_data(root,out):
    require(not out.exists(),'Use a new revision data directory')
    parent=root/'data/gnn/virtual-prepared/catalog.json'
    original=read_json(parent)
    source_map={s['run_id']:s for s in original['sources']}
    selected={}
    for name in PARTITIONS[:4]:
        for rule in original['partitions'][name]:
            selected.setdefault(rule['run_id'],[]).append(copy.deepcopy(rule))
    for name in ('stage2_train','stage2_val'):
        for rule in original['partitions'][name]:
            if not rule['run_id'].endswith('-control'):continue
            destination='stage1_train' if name=='stage2_train' else 'stage1_val' if '-from_start-control' in rule['run_id'] else 'calibration'
            updated=copy.deepcopy(rule)
            selected.setdefault(rule['run_id'],[]).append(updated)
            updated['_destination']=destination
    result={'sources':[],'partitions':{name:[] for name in PARTITIONS},'smoke':False,'synthetic':True,
            'calibration_mode':'stratified_normal_contexts','parent_catalog_sha256':file_hash(parent),
            'protocol':{'normal_training_controls':'seeds 1-3','normal_validation_controls':'seed 4 from_start',
                        'normal_calibration_controls':'seed 4 later','excluded':'all attack runs and all seed-5 runs',
                        'fresh_test_seeds':[37,41]}}
    out.mkdir(parents=True)
    for i,(run,rules) in enumerate(selected.items()):
        src=copy.deepcopy(source_map[run])
        path=parent.parent/rules[0]['path']
        require(file_hash(path)==src['graph_sha256'],'Parent graph hash mismatch')
        require(all(g['normal'] and all(n['label']!=1 for n in g['nodes']) for g in read_jsonl(path)), 'Only complete normal sources may fit A/B')
        name=f'{i:03d}-graphs.jsonl'
        shutil.copy2(path,out/name)
        src['normal_context']='legitimate_burst_cold_start' if run.endswith('-control') else 'background'
        result['sources'].append(src)
        for rule in rules:
            dest=rule.pop('_destination',None)
            if dest is None:
                dest=next(k for k,rs in original['partitions'].items() if rule in rs and k in PARTITIONS[:4])
            rule['path']=name
            result['partitions'][dest].append(rule)
    write_json(out/'catalog.json',result)
    print({'catalog':str(out/'catalog.json'),'sources':len(result['sources']),'protocol':result['protocol']},flush=True)


def holdout(root,out):
    require(not out.exists(),'Use a new fresh holdout directory')
    out.mkdir(parents=True)
    profiles_path=root/'data/gnn/generator-profiles.json'
    profiles=read_json(profiles_path)
    topology=read_json(root/'network/testbed/topology.json')
    actors=[next(d for d in topology['devices'] if d.startswith(prefix)) for prefix in ('SamsungCamera_','SamsungSmartThings_','BelkinWemoSwitch_')]
    runs=[]
    design={'seeds':[37,41],'families':list(FAMILIES),'actors':actors,'onsets':['from_start','later'],
            'profiles_sha256':file_hash(profiles_path),'label':'fresh final test; not for model selection or thresholds'}
    write_json(out/'design.json',design)
    for seed in design['seeds']:
        for family in FAMILIES:
            for actor in actors:
                for onset in design['onsets']:
                    for control in (False,True):
                        plan=build_plan(topology,1200,seed,profiles,family,actor,onset,control)
                        plan['profiles_file']=str(profiles_path.resolve())
                        plan['profiles_sha256']=file_hash(profiles_path)
                        path=out/'plans'/(plan['run_id']+'.json')
                        write_json(path,plan)
                        directory=out/'runs'/plan['run_id']
                        render(path,directory,virtual_start(1704067200,plan['session_id']))
                        runs.append({'run_id':plan['run_id'],'directory':str(directory.resolve()),'start':read_json(directory/'manifest.json')['start']})
                        print(f'Generated {len(runs)}/96 fresh holdout runs',flush=True)
    write_json(out/'runs.json',{'runs':runs,'design':design})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('.'))
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--mode',choices=('training','holdout'),required=True)
    a=parser.parse_args()
    (training_data if a.mode=='training' else holdout)(a.root.resolve(),a.out.resolve())

if __name__=='__main__':main()

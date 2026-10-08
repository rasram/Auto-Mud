"""Check measured feature observability on development PCAPs before training."""
from pathlib import Path
import argparse
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ml.schema import read_json,read_jsonl,write_json,file_hash,require
from ml.graph.build import build_snapshots
from ml.dataset_prep.extract import extract
from network.testbed.collection_plan import build_plan
from network.testbed.virtual_capture import render


def check(out):
    out=Path(out); require(not out.exists(),'Choose a fresh pilot directory')
    topology=read_json('network/testbed/topology.json'); profiles_path=Path('data/gnn/generator-profiles.json').resolve()
    profiles=read_json(profiles_path); actor=next(d for d in topology['devices'] if d.startswith('SamsungCamera_'))
    result={}
    for family in ('exfiltration','beaconing'):
        graphs=[]
        for control in (False,True):
            plan=build_plan(topology,600,23,profiles,family,actor,'from_start',control)
            plan.update(profiles_file=str(profiles_path),profiles_sha256=file_hash(profiles_path))
            p=out/'plans'/(plan['run_id']+'.json'); write_json(p,plan)
            directory=out/plan['run_id']; render(p,directory,1704067200)
            extract([directory/'capture.pcap'],directory/'zeek',zeek='/opt/zeek/bin/zeek')
            m=read_json(directory/'manifest.json')
            rows=(r for r in read_jsonl(directory/'zeek/telemetry.jsonl') if m['start']<=r['window_start']<m['end'])
            graphs.append(list(build_snapshots(rows,m,list(read_jsonl(directory/'labels.jsonl')))))
        def inputs(g):
            return ([(n['device_type'],n.get('service_category'),n['features'],n['feature_mask'],n['active'],n['available']) for n in g['nodes']],
                    [(e['source'],e['target']) for e in g['edges']])
        identical=sum(inputs(a)==inputs(b) for a,b in zip(*graphs))
        result[family]={'windows':len(graphs[0]),'identical_model_inputs':identical,'identical_fraction':identical/len(graphs[0])}
        require(identical<len(graphs[0]),f'{family} remains unobservable in the development pilot')
    write_json(out/'observability.json',result); print(result,flush=True)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--out',required=True)
    check(p.parse_args().out)

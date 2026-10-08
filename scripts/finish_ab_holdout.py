"""Resume independent fresh PCAP extraction in Linux/WSL, then build test graphs."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ml.schema import read_json,write_json,file_hash,require
from ml.dataset_prep.extract import extract
from ml.dataset_prep.catalog import prepare

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--zeek',required=True)
    parser.add_argument('--workers',type=int,default=4)
    a=parser.parse_args()
    runs=read_json(a.root/'runs.json')['runs']
    policy=Path(__file__).resolve().parents[1]/'network/zeek/automud-window.zeek'
    def process(run):
        directory=a.root/'runs'/run['run_id']
        folder=directory/'zeek'
        if (folder/'telemetry.jsonl').exists() and (folder/'extraction.json').exists():
            metadata=read_json(folder/'extraction.json')
            require(metadata['policy_sha256']==file_hash(policy),'Cached extraction used a different policy')
            require(metadata['inputs'][0]['sha256']==file_hash(directory/'capture.pcap'),'Cached PCAP changed')
        else:
            if folder.exists(): folder=directory/'zeek-native'
            require(not folder.exists(),'Incomplete retry exists; preserve it and choose a fresh retry directory')
            extract([directory/'capture.pcap'],folder,zeek=a.zeek)
        m=read_json(directory/'manifest.json')
        return {'manifest':str((directory/'manifest.json').resolve()),'telemetry':str((folder/'telemetry.jsonl').resolve()),
                'labels':str((directory/'labels.jsonl').resolve()),'partitions':[{'name':'stage2_test','start':m['start'],'end':m['end']}]}
    sources=[None]*len(runs)
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        pending={pool.submit(process,run):i for i,run in enumerate(runs)}
        for done,future in enumerate(as_completed(pending),1):
            sources[pending[future]]=future.result()
            print(f'Extracted/verified {done}/{len(runs)} fresh holdouts',flush=True)
    write_json(a.root/'sources.json',{'sources':sources})
    prepare(a.root/'sources.json',a.root/'prepared')
    print('Fresh test graphs prepared',flush=True)

if __name__=='__main__':main()

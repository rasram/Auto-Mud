import copy
import random
import pytest
import torch
from ml.smoke import fixtures
from ml.dataset_prep.catalog import load_partition
from ml.dataset_prep.tensors import Normalizer,to_pyg
from ml.schema import TYPES,HISTORY_FEATURE,file_hash
from ml.model.graphsage import Detector,reconstruction_errors
from ml.training.runtime import stage1_batch_loss,known_relationships,train_stage1,load,calibrate

def objects(tmp_path):
    catalog=fixtures(tmp_path)
    graphs=load_partition(catalog,'stage1_train')[:8]
    scaler=Normalizer().fit(graphs,scale_floor=True)
    pairs=sorted({(TYPES.index(g['nodes'][e['source']]['device_type']),TYPES.index(g['nodes'][e['target']]['device_type'])) for g in graphs for e in g['edges']})
    return catalog,graphs,scaler,Detector(revision='robust',normal_type_pairs=pairs)

def test_stable_link_ignores_traffic_and_query_edge(tmp_path):
    _,graphs,scaler,model=objects(tmp_path)
    model.eval()
    d=to_pyg(graphs[0],scaler)
    pairs=d.positive_pairs
    expected=model.score_pairs(d.x,d.edge_index,pairs)
    x=d.x.clone(); x[:,:len(__import__("ml.schema",fromlist=["FEATURES"]).FEATURES)+3]=1000; x[:,__import__("ml.schema",fromlist=["MASK_OFFSET"]).MASK_OFFSET:]=0
    assert torch.equal(expected,model.score_pairs(x,d.edge_index,pairs))
    removed=d.edge_index[:,~(((d.edge_index[0]==0)&(d.edge_index[1]==1))|((d.edge_index[0]==1)&(d.edge_index[1]==0)))]
    assert torch.allclose(model.score_pairs(d.x,d.edge_index,pairs[:,:1]),model.score_pairs(d.x,removed,pairs[:,:1]))

def test_robust_scaler_and_inactive_loss(tmp_path):
    _,graphs,scaler,model=objects(tmp_path)
    assert scaler.state['scale_floor']
    assert all(s['std'][HISTORY_FEATURE]>=.2 for s in scaler.state['stats'].values())
    d=to_pyg(graphs[0],scaler)
    d.active[:]=False
    rec,_,_=stage1_batch_loss(model,[graphs[0]],[d],known_relationships(graphs),random.Random(0))
    assert rec.item()==0

def test_robust_checkpoint_roundtrip(tmp_path):
    catalog,_,_,_=objects(tmp_path/'data')
    checkpoint=tmp_path/'model.pt'
    train_stage1(catalog,checkpoint,epochs=2,smoke=True,revision='robust',device='cpu')
    model,_,artifact=load(checkpoint)
    assert model.revision=='robust' and artifact['normalizer']['scale_floor']
    assert 'final_train' in artifact['quality_gate']
    calibrate(catalog,checkpoint,tmp_path/'calibrated.pt',device='cpu')


def test_unexpected_type_edge_cannot_pollute_known_link_score(tmp_path):
    _,graphs,scaler,model=objects(tmp_path)
    model.eval()
    d=to_pyg(graphs[0],scaler)
    pair=d.positive_pairs[:,:1]
    expected=model.score_pairs(d.x,d.edge_index,pair)
    unexpected=torch.tensor([[0,2],[2,0]],dtype=torch.long)
    assert torch.allclose(expected,model.score_pairs(d.x,torch.cat((d.edge_index,unexpected),dim=1),pair))

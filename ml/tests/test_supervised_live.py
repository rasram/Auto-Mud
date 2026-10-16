"""Supervised model history, opportunity rules and profile/bundle lifecycle."""
import copy
import json
from pathlib import Path
import torch
import pytest
from ml.inference import GNNBundle
from ml.live.graphs import StreamingGraph
from ml.live.engine import LiveEngine
from ml.live.examples import example_window
from ml.live.bundles import export_bundle
from ml.schema import file_hash
from ml.supervised.tensors import tensor

ROOT=Path(__file__).resolve().parents[2]
START=1700000040


@pytest.fixture
def model():
    torch.set_num_threads(1)
    return GNNBundle(ROOT/'models/gnn')


def test_receiver_only_b_is_null_but_a_is_scored(model):
    graph,_=StreamingGraph().build(example_window(START),profile=model.profile)
    result=model.score_graph(graph)
    origin={graph['nodes'][e['source']]['device_id'] for e in graph['edges']}
    for row in result['devices']:
        if row['status']=='ok':
            assert row['behavioral_score'] is not None
            assert (row['link_anomaly'] is not None)==(row['device_id'] in origin)


def test_supervised_prior_is_causal_bounded_and_survives_resume(model):
    builder=StreamingGraph();last=None
    for i in range(80):
        if i==41:builder=StreamingGraph.restore(json.loads(json.dumps(builder.dump())))
        graph,history=builder.build(example_window(START+60*i),profile=model.profile)
        data=tensor(graph,graph['prior_graphs'],model.predictor.scaler,model.profile)
        assert data.x.shape[1]==149 and data.history_x.shape[1:]==(15,147)
        assert len(graph['prior_graphs'])==min(i,15)
        assert all('prior_graphs' not in g for g in graph['prior_graphs'])
        assert all(g['window_start']<graph['window_start'] for g in graph['prior_graphs'])
        assert all(v['prior_windows']==min(i,15) for v in history['history'].values())
        assert not any('temporal_history' in n for g in builder.model_past for n in g['nodes'])
        last=graph
    assert all(v['fully_warmed'] for v in history['history'].values())
    assert len(json.dumps(builder.dump()))<1000000
    before=model.score_graph(last)
    altered=copy.deepcopy(last)
    for g in [altered,*altered['prior_graphs']]:
        g['normal']=True;g['attack_family']='irrelevant';g['run_id']='annotation-independent-run'
        for n in g['nodes']:n.update(label=1,behavior_label=1,relationship_label=1)
    after=model.score_graph(altered)
    assert before['devices']==after['devices']


def test_identity_change_invalidates_only_affected_model_history(model):
    builder=StreamingGraph()
    for i in range(3):builder.build(example_window(START+60*i),profile=model.profile)
    request=example_window(START+180)
    request['inventory'][0]['addresses'][0]['ip']='10.0.0.13'
    graph,state=builder.build(request,profile=model.profile)
    assert state['history']['demo-camera']['prior_windows']==0
    assert state['history']['demo-hub']['prior_windows']==3
    data=tensor(graph,graph['prior_graphs'],model.predictor.scaler,model.profile)
    index={n['device_id']:i for i,n in enumerate(graph['nodes'])}
    assert data.history_available[index['demo-camera']].sum()==0
    assert data.history_available[index['demo-hub']].sum()==3


def test_profile_swap_cold_starts_model_history_and_restart_keeps_reset(tmp_path,model):
    config=dict(_root=str(ROOT),bundle='models/gnn',allowed_bundle_roots=['models',str(tmp_path)],
        state_file=str(tmp_path/'state.json'),torch_threads=1,device='cpu',max_streams=2)
    engine=LiveEngine(config,now=lambda:START+100000)
    path=tmp_path/'new-profile'
    export_bundle(ROOT/'models/gnn',None,path,'profile-change-test')
    profile=json.loads((path/'flow-profiles.json').read_text());profile['source']='explicitly_new_test_profile'
    (path/'flow-profiles.json').write_text(json.dumps(profile))
    manifest=json.loads((path/'manifest.json').read_text())
    f=next(r for r in manifest['files'] if r['path']=='flow-profiles.json')
    f.update(sha256=file_hash(path/'flow-profiles.json'),bytes=(path/'flow-profiles.json').stat().st_size)
    (path/'manifest.json').write_text(json.dumps(manifest))
    try:
        engine.submit(example_window(START));stage=engine.stage(str(path))
        result=engine.activate(stage['model']['bundle_id'])
        assert not result['feature_history_preserved'] and result['model_history_reset_on_next_window']
        # A second stage before the first new minute must not probe old-profile
        # features left in last_graph by the previous active model.
        next_path=tmp_path/'same-new-profile'
        export_bundle(path,None,next_path,'next-profile-release')
        assert engine.stage(str(next_path))['status']=='staged'
        response,_=engine.submit(example_window(START+60))
        assert all(r['history']['prior_windows']==0 for r in response['devices'])
        engine.close();engine=LiveEngine(config,now=lambda:START+100000)
        assert engine.submit(example_window(START+60))==(response,True)
        response,_=engine.submit(example_window(START+120))
        assert all(r['history']['prior_windows']==1 for r in response['devices'])
    finally:engine.close()


def test_missing_or_duplicate_explicit_history_is_rejected(model):
    graph,_=StreamingGraph().build(example_window(START),profile=model.profile)
    graph.pop('prior_graphs')
    with pytest.raises(ValueError,match='Explicit causal'):model.score_graph(graph)


def test_precomputed_features_cannot_mix_profiles(model):
    builder=StreamingGraph()
    builder.build(example_window(START),profile=model.profile)
    graph,_=builder.build(example_window(START+60),profile=model.profile)
    graph['prior_graphs'][0]['flow_profile_sha256']='wrong-profile'
    with pytest.raises(ValueError,match='graph/profile mismatch'):model.score_graph(graph)


def test_candidate_rejects_nonfinite_profile_before_activation(tmp_path):
    target=tmp_path/'candidate'
    export_bundle(ROOT/'models/gnn',None,target,'invalid-profile')
    profile=json.loads((target/'flow-profiles.json').read_text())
    profile['external_tx_baseline_by_device']['unseen-probe-device']=float('nan')
    (target/'flow-profiles.json').write_text(json.dumps(profile))
    manifest=json.loads((target/'manifest.json').read_text())
    entry=next(v for v in manifest['files'] if v['path']=='flow-profiles.json')
    entry.update(sha256=file_hash(target/'flow-profiles.json'),bytes=(target/'flow-profiles.json').stat().st_size)
    (target/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='Invalid frozen profile baseline'):
        GNNBundle(target,allow_candidate=True)

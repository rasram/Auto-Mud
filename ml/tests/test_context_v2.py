import copy
from ml.schema import VERSION, FEATURES, SERVICES, X_NAMES, validate_manifest
from ml.graph.build import build_snapshots
from ml.graph.context import extend_features
from ml.dataset_prep.tensors import Normalizer, to_pyg
from ml.tests.test_pipeline import manifest, record
from network.testbed.collection_plan import build_plan, label_intervals
from ml.schema import read_json
from pathlib import Path


def test_service_nodes_preserve_external_relationship_without_ip_features():
    m=manifest(); r=record(resp_h='10.0.0.100',resp_p=443)
    g=next(build_snapshots([r],m))
    external=next(n for n in g['nodes'] if n['device_type']=='external_service')
    assert external['service_category']=='tls' and not external['active']
    assert any(g['nodes'][e['target']]['device_type']=='external_service' for e in g['edges'])
    scaler=Normalizer().fit([g]); data=to_pyg(g,scaler)
    assert data.x.shape[1]==len(X_NAMES)
    index=FEATURES.index('external_tx_ip_bytes')
    assert g['nodes'][0]['features'][index]==r['orig_ip_bytes']
    assert not any('10.0.0.100' in name for name in X_NAMES)


def test_causal_rolling_features_do_not_see_future():
    m=manifest(); first=record(); later=record(240,orig_ip_bytes=10**8)
    a=list(build_snapshots([first,later],m))
    b=list(build_snapshots([first,record(240,orig_ip_bytes=1)],m))
    assert a[0]==b[0] and a[1]==b[1]
    ix=FEATURES.index('rolling_tx_mean_5m')
    assert a[2]['nodes'][0]['features'][ix]==first['orig_ip_bytes']/2
    assert not a[0]['nodes'][0]['feature_mask'][ix]


def test_actor_victim_and_relationship_labels_are_separate():
    topology=read_json(Path(__file__).resolve().parents[2]/'network/testbed/topology.json')
    actor=topology['devices'][0]
    plan=build_plan(topology,600,11,scenario='lateral_connections',actor=actor)
    labels=label_intervals(plan,1704067200)
    victim=next(r for r in labels if r.get('affected_role')=='victim')
    assert victim['label']==0 and victim['behavior_intervals']
    malicious=next(r for r in labels if r['label']==1)
    assert malicious['relationship_label']==1
    plan=build_plan(topology,600,11,scenario='exfiltration',actor=actor)
    malicious=next(r for r in label_intervals(plan,1704067200) if r['label']==1)
    assert malicious['behavior_label']==1 and malicious['relationship_label']==0


def test_attack_control_ports_overlap_but_behavior_is_observable():
    topology=read_json(Path(__file__).resolve().parents[2]/'network/testbed/topology.json')
    for family in ('exfiltration','beaconing'):
        attack=build_plan(topology,600,11,scenario=family,actor=topology['devices'][0])
        control=build_plan(topology,600,11,scenario=family,actor=topology['devices'][0],normal_control=True)
        a=[e for e in attack['events'] if e['kind']==family]
        c=[e for e in control['events'] if e['kind']=='normal_control']
        assert a[0]['port']==c[0]['port']
        assert [e['offset'] for e in a]!=[e['offset'] for e in c]


def test_open_scan_ports_are_not_marked_as_transport_failures():
    topology=read_json(Path(__file__).resolve().parents[2]/'network/testbed/topology.json')
    plan=build_plan(topology,600,11,scenario='port_scan',actor=topology['devices'][0])
    listeners={tuple(e) for e in plan['service_endpoints']}
    probes=[e for e in plan['events'] if e['kind']=='port_scan']
    assert any(e['expect_failure'] for e in probes)
    assert any(not e['expect_failure'] for e in probes)
    assert all(((e['proto'],e['port']) not in listeners)==e['expect_failure'] for e in probes)

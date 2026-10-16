"""Inference feature contract for the frozen supervised C/E2 family."""
import hashlib
import json
import math
from ml.ab_targets.schema import FEATURES as V4_FEATURES
from ml.schema import LOG_FEATURES as OLD_LOG, require

VERSION='automud.supervised-graph.v1'
FEATURES=V4_FEATURES+('inbound_peer_service_novel_fraction','outbound_peer_service_novel_fraction',
    'inbound_peer_service_rarity','outbound_peer_service_rarity','sustained_external_tx_excess_15m',
    'inbound_flows_change_15m','inbound_peer_service_concentration_5m','external_tx_excess_1m',
    'outgoing_local_peer_count','incoming_local_peer_count','initiator_fanout_context')
# Freeze the actual training projection: v4's receiver log columns and v6 counts.
LOG_FEATURES=OLD_LOG+(44,46,58,59,60)
SCHEMA_HASH=hashlib.sha256(json.dumps(dict(version=VERSION,features=FEATURES,
    log_features=LOG_FEATURES,history_windows=15,transform='asinh(clean_type_or_global_z)',
    model='direct_detection.Detector(use_graph=False)',clock='native UTC or observed live UTC'),sort_keys=True).encode()).hexdigest()


def validate_graph(graph):
    require(graph.get('schema_version')==VERSION and graph.get('schema_hash')==SCHEMA_HASH,'Expected supervised C graph')
    require(isinstance(graph.get('prior_graphs'),list) and len(graph['prior_graphs'])<=15,'Explicit causal supervised history required')
    starts=[]
    for value in [*graph['prior_graphs'],graph]:
        require(value['run_id']==graph['run_id'] and value['session_id']==graph['session_id'],'History identity differs')
        starts.append(value['window_start'])
        require(value['schema_version']==VERSION and value['schema_hash']==SCHEMA_HASH,'History feature contract differs')
        ids=[n['device_id'] for n in value['nodes']]
        require(len(ids)==len(set(ids)),'Repeated graph identity')
        for node in value['nodes']:
            require(len(node['features'])==len(node['feature_mask'])==61,'Invalid supervised feature width')
            require(all(math.isfinite(v) for v in node['features']),'Nonfinite supervised features')
        for edge in value['edges']:
            require(0<=edge['source']<len(ids) and 0<=edge['target']<len(ids),'Invalid graph endpoint')
    require(starts==sorted(set(starts)) and all(t<graph['window_start'] for t in starts[:-1]),'Future or duplicate supervised history')
    return graph

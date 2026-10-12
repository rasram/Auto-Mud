"""v4 adds receiver evidence and preserves an exact v3 view for frozen Head B."""
import copy
import hashlib
import json
import math
from ml import schema as old

VERSION = 'automud.graph.v4'
RECEIVER_FEATURES = ('unique_initiators', 'new_initiator_fraction', 'unique_inbound_ports',
                     'inbound_failed_fraction', 'inbound_flow_fraction', 'inbound_flows_change_5m')
FEATURES = old.FEATURES + RECEIVER_FEATURES
TEMPORAL_FEATURES = old.TEMPORAL_FEATURES + ('unique_initiators', 'unique_inbound_ports',
                                          'inbound_flows', 'inbound_failed_fraction')
X_NAMES = FEATURES + old.X_NAMES[len(old.FEATURES):old.MASK_OFFSET] + tuple('valid_'+f for f in FEATURES)
MASK_OFFSET = len(X_NAMES)-len(FEATURES)
LOG_FEATURES = old.LOG_FEATURES + (len(old.FEATURES), len(old.FEATURES)+2)
SCHEMA_HASH = hashlib.sha256(json.dumps(dict(version=VERSION, features=X_NAMES,
    history_features=TEMPORAL_FEATURES, history_windows=old.HISTORY_WINDOWS,
    log_features=LOG_FEATURES, window_seconds=60,
    receiver_history='strictly_prior_complete_minutes;reset_on_unavailability'), sort_keys=True).encode()).hexdigest()


def validate_graph(graph):
    old.require(graph['schema_version']==VERSION and graph['schema_hash']==SCHEMA_HASH, 'Expected v4 graph')
    for node in graph['nodes']:
        old.require(len(node['features'])==len(node['feature_mask'])==len(FEATURES), 'Invalid v4 feature dimensions')
        old.require(all(math.isfinite(v) for v in node['features']),'Nonfinite v4 features')
        for row in node.get('temporal_history', []):
            old.require(len(row['features'])==len(row['feature_mask'])==len(TEMPORAL_FEATURES), 'Invalid v4 history')
            old.require(row['window_start']<graph['window_start'], 'Future history leakage')
    return graph


def project_v3(graph):
    """No inference or rescaling: drop only newly introduced columns/history."""
    validate_graph(graph)
    result = copy.deepcopy(graph)
    result.update(schema_version=old.VERSION, schema_hash=old.SCHEMA_HASH)
    for node in result['nodes']:
        node['features'] = node['features'][:len(old.FEATURES)]
        node['feature_mask'] = node['feature_mask'][:len(old.FEATURES)]
        for row in node.get('temporal_history', []):
            row['features'] = row['features'][:len(old.TEMPORAL_FEATURES)]
            row['feature_mask'] = row['feature_mask'][:len(old.TEMPORAL_FEATURES)]
    return result


def contract():
    return dict(schema_version=VERSION, schema_hash=SCHEMA_HASH, raw_features=FEATURES,
                tensor_columns=X_NAMES, temporal_features=TEMPORAL_FEATURES,
                history_windows=old.HISTORY_WINDOWS, window_seconds=60,
                legacy_projection=dict(version=old.VERSION, schema_hash=old.SCHEMA_HASH))

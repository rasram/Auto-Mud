"""Saved residual reference lookup using strictly prior observable history."""
import numpy as np
from ml.schema import require
from ml.ab_targets.schema import TEMPORAL_FEATURES

def operating_context(graph, index):
    """No labels, scenario names, current feature values or future history."""
    node = graph['nodes'][index]
    history = node.get('temporal_history', [])
    start = graph['window_start']
    require(all(row['window_start'] < start for row in history), 'Context history must be strictly prior')
    require(all(row.get('available', True) for row in history), 'Unavailable context history must be reset')
    age = 'cold' if len(history) < 3 else 'settling' if len(history) < 6 else 'warm'
    if not history:
        return age + '|load=unknown|direction=unknown'
    columns = [TEMPORAL_FEATURES.index(f) for f in ('active_flows', 'initiated_flows', 'inbound_flows')]
    values = [[] for _ in columns]
    for row in history[-5:]:
        for output, column in zip(values, columns):
            if row['feature_mask'][column]:
                value = row['features'][column]
                require(np.isfinite(value) and value >= 0, 'Invalid prior flow count')
                output.append(value)
    load = 'unknown' if not values[0] else 'quiet' if np.median(values[0]) == 0 else 'light' if np.median(values[0]) <= 4 else 'busy'
    if not values[1] or not values[2]:
        direction = 'unknown'
    else:
        outgoing, incoming = np.median(values[1]), np.median(values[2])
        direction = 'quiet' if outgoing + incoming == 0 else 'receive' if incoming > 2*outgoing else 'send' if outgoing > 2*incoming else 'mixed'
    return age + '|load=' + load + '|direction=' + direction



def reference_group(reference, graph, index):
    node = graph['nodes'][index]
    if reference.get('context_groups'):
        key = node['device_id'] + '|' + operating_context(graph, index)
        if key in reference['context_groups']:
            return reference['context_groups'][key]
    return reference['groups'].get('device:' + node['device_id'],
        reference['groups'].get(node['device_type'], reference['groups']['global']))


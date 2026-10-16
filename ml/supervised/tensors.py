"""Exact C input projection; live UTC uses the same sine/cosine encoder."""
from collections import defaultdict
import copy
import math
import numpy as np
import torch
from torch_geometric.data import Data
from ml.schema import TYPES, SERVICES, service_category, require
from ml.supervised.schema import FEATURES, LOG_FEATURES, VERSION, SCHEMA_HASH
from ml.clock import native_offsets

def transformed(node):
    values=np.asarray(node['features'],float).copy()
    values[list(LOG_FEATURES)]=np.log1p(values[list(LOG_FEATURES)])
    require(np.isfinite(values).all(),'Nonfinite supervised input')
    return values

def clock(graph,node):
    if node['device_type']=='external_service': return 0.
    time=graph['window_start']+native_offsets(graph)[node['device_id']]
    return 2*math.pi*(time%86400)/86400

def edge_values(edge):
    services=set()
    for value in edge['ports']:
        proto,port=value.split('/',1)
        services.add(service_category(proto,None if port in ('None','null','') else int(port)))
    return [math.log1p(edge[k]) for k in ('ip_bytes','packets','flow_count')]+[float(s in services) for s in SERVICES]

HISTORY = 15
BASE_WIDTH = 2 * len(FEATURES) + 3 + len(TYPES) + len(SERVICES) + 2
INPUT_WIDTH = BASE_WIDTH + 2
EDGE_WIDTH = 3 + len(SERVICES)


def v6(graph, profile):
    """Pure projection of archived v6 descriptors, without audit-runner imports."""
    assert all(len(n['features'])==57 for n in graph['nodes'])
    value=copy.deepcopy(graph);outgoing=defaultdict(set);incoming=defaultdict(set)
    for edge in graph['edges']:
        u,v=edge['source'],edge['target']
        if all(graph['nodes'][i]['device_type']!='external_service' for i in (u,v)):
            outgoing[u].add(v);incoming[v].add(u)
    for i,node in enumerate(value['nodes']):
        support=node['available'] and node['device_type']!='external_service'
        baseline=profile['external_tx_baseline_by_device'].get(node['device_id'])
        volume=math.log1p(node['features'][FEATURES.index('external_tx_ip_bytes')])-math.log1p(baseline) if support and node['active'] and baseline is not None else None
        fanout=max([len(outgoing[i])]+[len(outgoing[u]) for u in incoming[i]])
        node['features'] += [float(volume or 0),float(len(outgoing[i])),float(len(incoming[i])),float(fanout)]
        node['feature_mask'] += [volume is not None,support,support,support]
    value.update(schema_version=VERSION,schema_hash=SCHEMA_HASH)
    return value


def identity(node):
    return (node['device_id'], node['device_type'], node.get('identity_epoch'))


class Normalizer:
    def __init__(self, state):
        self.state = state

    def row(self, graph, node, profile, services=()):
        state = self.state['stats'].get(node['device_type'], self.state['stats']['global'])
        mask = np.asarray(node['feature_mask'], np.float32) * bool(node['available'])
        z = (transformed(node) - state['mean']) / state['std']
        values = np.where(mask.astype(bool), np.arcsinh(z), 0.)
        angle = clock(graph, node)
        baseline = profile['external_tx_baseline_by_device'].get(node['device_id'])
        meta = [math.sin(angle), math.cos(angle), float(node['active'])]
        meta += [float(t == node['device_type']) for t in TYPES]
        meta += [float(s in services) for s in SERVICES]
        meta += [math.log1p(baseline) / 20 if baseline is not None else 0., float(baseline is not None)]
        output = np.r_[values, meta, mask].astype(np.float32)
        assert len(output) == BASE_WIDTH and np.isfinite(output).all()
        return output


def tensor(graph, history, scaler, profile):
    """Only this explicit feature projection crosses the model-input boundary."""
    assert all(p['run_id'] == graph['run_id'] and p['window_start'] < graph['window_start'] for p in history)
    t, nodes = graph['window_start'], graph['nodes']
    outgoing = defaultdict(set)
    for edge in graph['edges']:
        for port in edge['ports']:
            proto, value = port.split('/', 1)
            outgoing[edge['source']].add(service_category(proto, None if value in ('None','null','') else int(value)))
    own = np.stack([scaler.row(graph, node, profile, outgoing[i]) for i, node in enumerate(nodes)])
    hx = np.zeros((len(nodes), HISTORY, BASE_WIDTH), np.float32)
    hm = np.zeros((len(nodes), HISTORY), np.float32)
    lookup = {g['window_start']:g for g in history}
    assert len(lookup) == len(history)
    for i, node in enumerate(nodes):
        if not node['available']:
            continue
        # Walk backwards until the first missing observation or changed binding.
        # An old identity cannot resume across a missing or unavailable minute.
        for age in range(1, HISTORY + 1):
            previous = lookup.get(t - age * 60)
            if previous is None:
                break
            match = [(j,n) for j,n in enumerate(previous['nodes']) if n['device_id'] == node['device_id']]
            if len(match) != 1 or not match[0][1]['available'] or identity(match[0][1]) != identity(node):
                break
            j, old = match[0]
            services = set()
            for edge in previous['edges']:
                if edge['source'] != j:
                    continue
                for port in edge['ports']:
                    proto, value = port.split('/', 1)
                    services.add(service_category(proto, None if value in ('None','null','') else int(value)))
            hx[i, HISTORY-age] = scaler.row(previous, old, profile, services)
            hm[i, HISTORY-age] = 1.
    history_count = hm.sum(1)
    x = np.c_[own, (history_count == 0).astype(float), history_count/HISTORY].astype(np.float32)
    edges = [e for e in graph['edges'] if nodes[e['source']]['available'] and nodes[e['target']]['available']]
    edge_index = torch.tensor([(e['source'],e['target']) for e in edges], dtype=torch.long).t().contiguous() if edges else torch.empty((2,0), dtype=torch.long)
    edge_attr = torch.tensor([edge_values(e) for e in edges], dtype=torch.float32) if edges else torch.empty((0,EDGE_WIDTH))
    return Data(x=torch.from_numpy(x), history_x=torch.from_numpy(hx), history_available=torch.from_numpy(hm),
                edge_index=edge_index, edge_attr=edge_attr, num_nodes=len(nodes))

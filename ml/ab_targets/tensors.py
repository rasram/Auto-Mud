"""v4 normalizer fitted only on normal training; prior history never sees current targets."""
import math
import numpy as np
from ml.schema import TYPES, SERVICES, require
from ml.ab_targets.schema import FEATURES, LOG_FEATURES, TEMPORAL_FEATURES, SCHEMA_HASH, validate_graph


def transformed(node):
    values = np.asarray(node['features'],dtype=np.float64).copy()
    require(values.shape==(len(FEATURES),) and np.isfinite(values).all(),'Invalid v4 feature vector')
    require((values[list(LOG_FEATURES)]>=0).all(),'Negative count')
    values[list(LOG_FEATURES)] = np.log1p(values[list(LOG_FEATURES)])
    return values


class Normalizer:
    def __init__(self,state=None): self.state=state


    def node(self,node,start):
        require(self.state['schema_hash']==SCHEMA_HASH,'Normalizer schema mismatch')
        stats=self.state['stats'].get(node['device_type'],self.state['stats']['global'])
        mask=np.asarray(node['feature_mask'],dtype=np.float32)*node['available']
        target=((transformed(node)-stats['mean'])/stats['std'])*mask
        if self.state.get('clock_mode')=='native_source':
            require('source_clock_offset_seconds' in node,'Native clock requires source provenance')
            start+=node['source_clock_offset_seconds']
        angle=2*math.pi*(start%86400)/86400
        metadata=[math.sin(angle),math.cos(angle),float(node['active'])]
        metadata += [float(t==node['device_type']) for t in TYPES]
        metadata += [float(s==node.get('service_category')) for s in SERVICES]
        return np.r_[target,metadata,mask].astype(np.float32),target.astype(np.float32),mask


def to_pyg(graph,scaler):
    import torch
    from torch_geometric.data import Data
    validate_graph(graph); start=graph['window_start']
    nodes=graph['nodes']
    if scaler.state.get('clock_mode')=='native_source':
        from ml.clock import native_offsets
        offsets = native_offsets(graph)
        nodes = [dict(n, source_clock_offset_seconds=offsets[n['device_id']]) for n in nodes]
    rows=[scaler.node(n,start) for n in nodes]
    histories=[]; indices=[FEATURES.index(f) for f in TEMPORAL_FEATURES]
    for node in nodes:
        output=np.zeros((15,2*len(indices)),dtype=np.float32)
        previous=node.get('temporal_history',[])
        require(len(previous)<=15,'Too much history')
        for i,row in enumerate(previous,15-len(previous)):
            require(row['window_start']==start-(15-i)*60,'Noncausal/noncontiguous history')
            values=[0.]*len(FEATURES); masks=[False]*len(FEATURES)
            for j,k in enumerate(indices): values[k]=row['features'][j]; masks[k]=row['feature_mask'][j]
            _,target,mask=scaler.node(dict(node,features=values,feature_mask=masks),row['window_start'])
            output[i]=np.r_[target[indices],mask[indices]]
        histories.append(output)
    pairs={(e['source'],e['target']) for e in graph['edges']}
    edges=sorted(pairs|{(v,u) for u,v in pairs})
    adjacency=torch.tensor(edges,dtype=torch.long).t().contiguous() if edges else torch.empty((2,0),dtype=torch.long)
    return Data(x=torch.from_numpy(np.stack([r[0] for r in rows])),edge_index=adjacency,
        target=torch.from_numpy(np.stack([r[1] for r in rows])),feature_mask=torch.from_numpy(np.stack([r[2] for r in rows])),
        temporal_history=torch.from_numpy(np.stack(histories)),
        active=torch.tensor([n['active'] for n in graph['nodes']]),available=torch.tensor([n['available'] for n in graph['nodes']]),
        num_nodes=len(rows))

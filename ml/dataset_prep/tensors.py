import math
import numpy as np

from ml.schema import FEATURES, TYPES, SERVICES, LOG_FEATURES, SCHEMA_HASH, require, HISTORY_WINDOWS, TEMPORAL_FEATURES


def transformed(node):
    a = np.asarray(node["features"], dtype=np.float64).copy()
    require(a.shape == (len(FEATURES),) and np.isfinite(a).all(), "Invalid raw feature vector")
    require((a[list(LOG_FEATURES)] >= 0).all(), "Negative count/duration")
    a[list(LOG_FEATURES)] = np.log1p(a[list(LOG_FEATURES)])
    return a


class Normalizer:
    def __init__(self, state=None):
        self.state = state


    def node(self, node, window_start):
        require(self.state["schema_hash"] == SCHEMA_HASH, "Scaler schema mismatch")
        typ = node["device_type"]
        stats = self.state["stats"].get(typ, self.state["stats"]["global"])
        mask = np.asarray(node["feature_mask"], dtype=np.float32) * bool(node["available"])
        normalized = (transformed(node) - stats["mean"]) / stats["std"]
        normalized *= mask
        angle = 2 * math.pi * (window_start % 86400) / 86400
        types = [float(t == typ) for t in TYPES]
        x = np.r_[normalized, math.sin(angle), math.cos(angle), float(node["active"]), types, [float(s == node.get("service_category")) for s in SERVICES], mask]
        return x.astype(np.float32), normalized.astype(np.float32), mask


def history_tensor(node, window_start, scaler):
    output=np.zeros((HISTORY_WINDOWS,len(TEMPORAL_FEATURES)*2),dtype=np.float32)
    history=node.get('temporal_history',[])
    require(len(history)<=HISTORY_WINDOWS, 'Too many history windows')
    for i,row in enumerate(history, HISTORY_WINDOWS-len(history)):
        require(row['window_start']<window_start, 'Future/current window in temporal input')
        require(row['window_start']==window_start-(HISTORY_WINDOWS-i)*60, 'Noncontiguous temporal history')
        indices=[FEATURES.index(f) for f in TEMPORAL_FEATURES]
        require(len(row['features'])==len(indices) and len(row['feature_mask'])==len(indices), 'Invalid compact history')
        features=[0.]*len(FEATURES);valid=[False]*len(FEATURES)
        for j,k in enumerate(indices): features[k]=row['features'][j];valid[k]=row['feature_mask'][j]
        previous=dict(node,features=features,feature_mask=valid)
        _,target,mask=scaler.node(previous,row['window_start'])
        output[i]=np.r_[target[indices],mask[indices]]
    return output


def to_pyg(graph, scaler):
    import torch
    from torch_geometric.data import Data
    require(graph["schema_hash"] == SCHEMA_HASH, "Snapshot schema mismatch")
    rows = [scaler.node(n, graph["window_start"]) for n in graph["nodes"]]
    # Observed attempts are graph evidence too; successful/attempt distinction is retained in metadata.
    pairs = {(e["source"], e["target"]) for e in graph["edges"]}
    adjacent = sorted(pairs | {(v, u) for u, v in pairs})
    edges = torch.tensor(adjacent, dtype=torch.long).t().contiguous() if adjacent else torch.empty((2, 0), dtype=torch.long)
    positive = torch.tensor(sorted(pairs), dtype=torch.long).t().contiguous() if pairs else torch.empty((2, 0), dtype=torch.long)
    return Data(x=torch.from_numpy(np.stack([r[0] for r in rows])), edge_index=edges,
                temporal_history=torch.from_numpy(np.stack([history_tensor(n,graph["window_start"],scaler) for n in graph["nodes"]])),
                positive_pairs=positive, target=torch.from_numpy(np.stack([r[1] for r in rows])),
                feature_mask=torch.from_numpy(np.stack([r[2] for r in rows])),
                available=torch.tensor([n["available"] for n in graph["nodes"]]),
                active=torch.tensor([n["active"] for n in graph["nodes"]]),
                y=torch.tensor([n["label"] for n in graph["nodes"]], dtype=torch.float32),
                num_nodes=len(rows))

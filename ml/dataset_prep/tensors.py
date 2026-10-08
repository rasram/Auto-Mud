import math
import numpy as np

from ml.schema import FEATURES, TYPES, SERVICES, LOG_FEATURES, SCHEMA_HASH, require


def transformed(node):
    a = np.asarray(node["features"], dtype=np.float64).copy()
    require(a.shape == (len(FEATURES),) and np.isfinite(a).all(), "Invalid raw feature vector")
    require((a[list(LOG_FEATURES)] >= 0).all(), "Negative count/duration")
    a[list(LOG_FEATURES)] = np.log1p(a[list(LOG_FEATURES)])
    return a


class Normalizer:
    def __init__(self, state=None):
        self.state = state

    def fit(self, graphs, min_type_rows=100, scale_floor=False):
        grouped = {"global": []}
        for g in graphs:
            require(g["schema_hash"] == SCHEMA_HASH, "Schema mismatch")
            require(g["normal"], "Scaler may only fit clean Stage-1 training graphs")
            for n in g["nodes"]:
                if n["active"] and n["available"]:
                    pair = (transformed(n), np.asarray(n["feature_mask"], bool))
                    grouped["global"].append(pair)
                    grouped.setdefault(n["device_type"], []).append(pair)
        require(grouped["global"], "No active normal training observations")
        stats = {}
        for typ, rows in grouped.items():
            if typ != "global" and len(rows) < min_type_rows:
                continue
            values = np.stack([r[0] for r in rows])
            masks = np.stack([r[1] for r in rows])
            count = masks.sum(0)
            mean = (values * masks).sum(0) / np.maximum(count, 1)
            std = np.sqrt((((values - mean) ** 2) * masks).sum(0) / np.maximum(count, 1))
            # Unit scale for constant features: tiny eps would inflate novel values arbitrarily.
            std[std < 1e-6] = 1.0
            if scale_floor:
                floors = np.full(len(FEATURES), .25)
                floors[[8,11,12,13,14]] = .2
                floors[17] = 1.
                std = np.maximum(std,floors)
            stats[typ] = {"mean": mean.tolist(), "std": std.tolist(), "count": count.tolist()}
        self.state = {"schema_hash": SCHEMA_HASH, "stats": stats, "min_type_rows": min_type_rows, "scale_floor": scale_floor}
        return self

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
                positive_pairs=positive, target=torch.from_numpy(np.stack([r[1] for r in rows])),
                feature_mask=torch.from_numpy(np.stack([r[2] for r in rows])),
                available=torch.tensor([n["available"] for n in graph["nodes"]]),
                active=torch.tensor([n["active"] for n in graph["nodes"]]),
                y=torch.tensor([n["label"] for n in graph["nodes"]], dtype=torch.float32),
                num_nodes=len(rows))

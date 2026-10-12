import torch
import copy
from torch import nn
from torch_geometric.nn import SAGEConv, GCNConv

from ml.schema import FEATURES, X_NAMES, HISTORY_FEATURE, MASK_OFFSET, TYPES, SERVICES, SERVICE_OFFSET, TEMPORAL_FEATURES


class Detector(nn.Module):
    """Versioned A/B model; legacy checkpoints keep their original behavior."""
    def __init__(self, architecture="sage", hidden=64, embedding=16, revision="legacy", normal_type_pairs=None, layers=2, aggregation="mean", temporal="none"):
        super().__init__()
        if architecture not in ("sage", "gcn", "mlp"):
            raise ValueError(f"Unknown architecture {architecture}")
        if revision not in ("legacy", "robust"):
            raise ValueError(f"Unknown model revision {revision}")
        if layers not in (1,2) or aggregation not in ('mean','mean_max') or temporal not in ('none','forecast'):
            raise ValueError('Invalid depth, aggregation or temporal option')
        self.layers,self.temporal=layers,temporal
        self.config = dict(architecture=architecture, hidden=hidden, embedding=embedding,
                           revision=revision, normal_type_pairs=normal_type_pairs, layers=layers, aggregation=aggregation, temporal=temporal)
        self.architecture, self.revision = architecture, revision
        def conv(a,b):
            return SAGEConv(a,b,aggr=['mean','max'] if aggregation=='mean_max' else 'mean') if architecture=='sage' else GCNConv(a,b)
        width=hidden if layers==2 else embedding
        self.layer1 = nn.Linear(len(X_NAMES), width) if architecture == "mlp" else conv(len(X_NAMES), width)
        self.layer2 = (nn.Linear(hidden, embedding) if architecture == "mlp" else conv(hidden, embedding)) if layers==2 else nn.Identity()
        self.decoder = nn.Sequential(nn.Linear(embedding, hidden), nn.ReLU(), nn.Linear(hidden, len(FEATURES)))
        self.link = nn.Bilinear(embedding, embedding, 1)
        self.classifier = nn.Sequential(nn.Linear(embedding, 32), nn.ReLU(), nn.Linear(32, 1))
        if temporal=='forecast':
            self.spatial_decoder=copy.deepcopy(self.decoder)
            self.temporal_encoder=nn.GRU(2*len(TEMPORAL_FEATURES),embedding,batch_first=True)
            self.temporal_context=nn.Linear(len(X_NAMES)-len(FEATURES)*2,embedding)
        if revision == "robust":
            self.self1 = nn.Linear(len(X_NAMES), width)
            self.self2 = nn.Linear(hidden, embedding)
            self.message_gate = nn.Parameter(torch.full((2,), -2.0))
            self.encoder_norm = nn.LayerNorm(width)
            self.dropout = nn.Dropout(.1)
            self.relationship1 = nn.Linear(len(X_NAMES),width) if architecture=="mlp" else conv(len(X_NAMES),width)
            self.relationship2 = (nn.Linear(hidden,embedding) if architecture=="mlp" else conv(hidden,embedding)) if layers==2 else nn.Identity()
            allowed = torch.zeros((len(TYPES), len(TYPES)), dtype=torch.bool)
            for a,b in normal_type_pairs or []:
                allowed[a,b] = allowed[b,a] = True
            self.register_buffer("allowed_type_adjacency", allowed)

    def encode(self, x, edge_index):
        if self.revision == "robust":
            bounded = torch.cat((x[:, :len(FEATURES)].clamp(-8,8), x[:,len(FEATURES):]),dim=1)
            first = self.layer1(bounded) if self.architecture == "mlp" else self.layer1(bounded,edge_index)
            gate = torch.sigmoid(self.message_gate)
            h = self.dropout(torch.relu(self.encoder_norm((1-gate[0])*self.self1(bounded)+gate[0]*first)))
            if self.layers==1: return h
            second = self.layer2(h) if self.architecture == "mlp" else self.layer2(h,edge_index)
            return (1-gate[1])*self.self2(h)+gate[1]*second
        if self.layers==1:
            return self.layer1(x) if self.architecture=="mlp" else self.layer1(x,edge_index)
        if self.architecture == "mlp":
            return self.layer2(torch.relu(self.layer1(x)))
        return self.layer2(torch.relu(self.layer1(x, edge_index)), edge_index)

    def reconstruct(self, x, edge_index, temporal_history=None):
        if self.temporal=='forecast':
            if temporal_history is None: raise ValueError('Forecast needs causal history tensor')
            _,h=self.temporal_encoder(temporal_history.clamp(-8,8))
            # Only clock/type/service metadata, no current volumes/masks/activity/edges.
            context=x[:,len(FEATURES):MASK_OFFSET].clone()
            context[:,2]=0
            return self.decoder(h[-1]+self.temporal_context(context))
        return self.decoder(self.encode(x,edge_index))

    def spatial_reconstruct(self,x,edge_index):
        return (self.spatial_decoder if self.temporal=='forecast' else self.decoder)(self.encode(x,edge_index))

    def relationship_encode(self, x, edge_index):
        if self.revision == "legacy":
            return self.encode(x,edge_index)
        type_start = len(FEATURES)+3
        stable = torch.zeros_like(x)
        stable[:,type_start:MASK_OFFSET] = x[:,type_start:MASK_OFFSET]
        types = stable[:,type_start:type_start+len(TYPES)].argmax(1)
        keep = self.allowed_type_adjacency[types[edge_index[0]],types[edge_index[1]]]
        stable_edges = edge_index[:,keep]
        first=self.relationship1(stable) if self.architecture=='mlp' else self.relationship1(stable,stable_edges)
        if self.layers==1: return first
        return self.relationship2(torch.relu(first)) if self.architecture=='mlp' else self.relationship2(torch.relu(first),stable_edges)

    def head_c_input(self, x):
        x = x.clone()
        history = [i for i,f in enumerate(FEATURES) if i==HISTORY_FEATURE or f.startswith("rolling_") or f.startswith("log_tx_change_") or f.startswith("stream_")]
        x[:, history] = 0
        x[:, [MASK_OFFSET+i for i in history]] = 0
        return x

    def compromised_logits(self, x, edge_index):
        with torch.no_grad():
            h = self.encode(self.head_c_input(x), edge_index)
        return self.classifier(h).flatten()

    def score_pairs(self, x, edge_index, pairs, chunk_size=32):
        """Each query relationship is removed in both directions before scoring."""
        if pairs.numel() == 0:
            return x.new_empty((0,))
        outputs = []
        n = x.shape[0]
        for chunk in pairs.t().split(chunk_size):
            u, v = chunk[:, 0, None], chunk[:, 1, None]
            keep = ~(((edge_index[0][None, :] == u) & (edge_index[1][None, :] == v)) |
                     ((edge_index[0][None, :] == v) & (edge_index[1][None, :] == u)))
            offsets = torch.arange(len(chunk), device=x.device)[:, None, None] * n
            replicas = edge_index[None, :, :] + offsets
            edges = replicas.permute(1, 0, 2).reshape(2, -1)[:, keep.reshape(-1)]
            h = self.relationship_encode(x.repeat(len(chunk), 1), edges)
            offset = torch.arange(len(chunk), device=x.device) * n
            outputs.append(self.link(h[chunk[:, 0] + offset], h[chunk[:, 1] + offset]).flatten())
        return torch.cat(outputs)

    def freeze_base(self):
        for name, p in self.named_parameters():
            p.requires_grad_(name.startswith("classifier."))
        self.eval()


def reconstruction_errors(model, data):
    predicted = model.reconstruct(data.x, data.edge_index, data.temporal_history)
    losses = (predicted - data.target).square() * data.feature_mask
    return losses.sum(1) / data.feature_mask.sum(1).clamp(min=1)

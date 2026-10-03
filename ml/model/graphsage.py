import torch
from torch import nn
from torch_geometric.nn import SAGEConv, GCNConv

from ml.schema import FEATURES, X_NAMES, HISTORY_FEATURE, MASK_OFFSET


class Detector(nn.Module):
    """No learned device IDs and no profile-deviation input."""
    def __init__(self, architecture="sage", hidden=64, embedding=16):
        super().__init__()
        if architecture not in ("sage", "gcn", "mlp"):
            raise ValueError(f"Unknown architecture {architecture}")
        self.config = dict(architecture=architecture, hidden=hidden, embedding=embedding)
        self.architecture = architecture
        conv = SAGEConv if architecture == "sage" else GCNConv
        self.layer1 = nn.Linear(len(X_NAMES), hidden) if architecture == "mlp" else conv(len(X_NAMES), hidden)
        self.layer2 = nn.Linear(hidden, embedding) if architecture == "mlp" else conv(hidden, embedding)
        self.decoder = nn.Sequential(nn.Linear(embedding, hidden), nn.ReLU(), nn.Linear(hidden, len(FEATURES)))
        self.link = nn.Bilinear(embedding, embedding, 1)
        self.classifier = nn.Sequential(nn.Linear(embedding, 32), nn.ReLU(), nn.Linear(32, 1))

    def encode(self, x, edge_index):
        if self.architecture == "mlp":
            return self.layer2(torch.relu(self.layer1(x)))
        return self.layer2(torch.relu(self.layer1(x, edge_index)), edge_index)

    def head_c_input(self, x):
        x = x.clone()
        x[:, HISTORY_FEATURE] = 0
        x[:, MASK_OFFSET + HISTORY_FEATURE] = 0
        return x

    def compromised_logits(self, x, edge_index):
        # A separate pass with the same frozen weights makes C independent of history.
        with torch.no_grad():
            h = self.encode(self.head_c_input(x), edge_index)
        return self.classifier(h).flatten()

    def score_pairs(self, x, edge_index, pairs, chunk_size=32):
        """Leave each query relationship out in BOTH directions, even at inference.

        Disconnected replicas vectorize the counterfactual embedding passes. This
        prevents an existing edge from disclosing its own existence to the scorer.
        """
        if pairs.numel() == 0:
            return x.new_empty((0,))
        outputs = []
        n = x.shape[0]
        for chunk in pairs.t().split(chunk_size):
            replicated_edges = []
            for k, (u, v) in enumerate(chunk):
                keep = ~(((edge_index[0] == u) & (edge_index[1] == v)) |
                         ((edge_index[0] == v) & (edge_index[1] == u)))
                replicated_edges.append(edge_index[:, keep] + k * n)
            edges = torch.cat(replicated_edges, dim=1)
            h = self.encode(x.repeat(len(chunk), 1), edges)
            offset = torch.arange(len(chunk), device=x.device) * n
            outputs.append(self.link(h[chunk[:, 0] + offset], h[chunk[:, 1] + offset]).flatten())
        return torch.cat(outputs)

    def freeze_base(self):
        for name, p in self.named_parameters():
            p.requires_grad_(name.startswith("classifier."))
        self.eval()


def reconstruction_errors(model, data):
    predicted = model.decoder(model.encode(data.x, data.edge_index))
    losses = (predicted - data.target).square() * data.feature_mask
    return losses.sum(1) / data.feature_mask.sum(1).clamp(min=1)

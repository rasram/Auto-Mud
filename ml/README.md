# ml/ — ML Engineering

**Owner:** Jayan Subramanian

Graph construction and the GraphSAGE anomaly detector (PyTorch Geometric).

The implemented v1 path is **database-free**. Start at
[the GNN runbook](../docs/gnn/README.md). Run `python -m ml --help` for data,
training, calibration, inference, and collection-plan commands.

| Subdirectory | Contents |
|---|---|
| `graph/` | Causal 60-second interval aggregation and direct graph construction |
| `dataset_prep/` | Canonical telemetry, verified actor labels, dataset audit, scaling, and splits |
| `model/` | GraphSAGE model (standard PyG architecture; custom GNN design is out of scope) |
| `training/` | Offline training, model-level validation, freezing weights |

System-level evaluation against baselines lives in `integration/evaluation/`.

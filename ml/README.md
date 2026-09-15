# ml/ — ML Engineering

**Owner:** Jayan Subramanian

Graph construction and the GraphSAGE anomaly detector (PyTorch Geometric).

| Subdirectory | Contents |
|---|---|
| `graph/` | Device communication graph construction in Neo4j |
| `dataset_prep/` | Preparing labeled graph-snapshot data from UNSW, N-BaIoT, and CICIoT2023 |
| `model/` | GraphSAGE model (standard PyG architecture; custom GNN design is out of scope) |
| `training/` | Offline training, model-level validation, freezing weights |

System-level evaluation against baselines lives in `integration/evaluation/`.

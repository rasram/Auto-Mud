# ml/model/

**Owner:** Jayan Subramanian

GraphSAGE model definition in PyTorch Geometric. It takes the current graph snapshot plus the per-device deviation scores and outputs a per-device **anomaly score in [0.0, 1.0]** that combines individual behavioral deviation with structural (relationship) anomaly.

GraphSAGE was chosen over GCN/GAT for its intrusion-detection performance and inductive support for unseen devices (§8). Custom GNN architecture design is out of scope.

Methodology: Stage 2, step 11.

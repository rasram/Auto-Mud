# ml/model/

**Owner:** Jayan Subramanian

`graphsage.py` implements a two-layer mean GraphSAGE encoder and independent
reconstruction, link-expectedness, and compromised-device classifier heads.
It consumes canonical graph snapshots, without Neo4j or profiling deviation scores.
Head C masks device-history features and trains on a frozen encoder.

See [architecture, training and inference](../../docs/gnn/TRAINING.md).

# Legacy frozen-B architecture

`graphsage.py` is retained for explicit legacy v1/v2 bundle loading and shared
historical projections. It is not the active supervised C model.

Current inference uses `ml/supervised/model.py` with
`Detector(use_graph=False)`: own-device encoder, causal GRU history and joint
A/B heads. Unused original message-module parameters are retained to load the
exact original C checkpoint. No learned neighbor messages are evaluated.

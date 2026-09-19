# data/artifacts/

**Owner:** Shared

Frozen Stage 0 outputs used by the live loop in inference-only mode:

- `models/`: frozen GraphSAGE weights (from `ml/training/`)
- `traffic_generation/`: calibrated device statistics consumed by the testbed traffic generators

Profiling outputs and validation reports are grouped under `data/processed/unsw/`.

Weight files are git-ignored. Share them through a separate channel.

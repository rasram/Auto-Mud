# data/artifacts/

**Owner:** Shared

Frozen Stage 0 outputs used by the live loop in inference-only mode:

- `profiles/`: frozen per-device-type MUD-like JSON profiles (from `profiling/profile_engine/`)
- `models/`: frozen GraphSAGE weights (from `ml/training/`)
- `traffic_generation/`: calibrated device statistics consumed by the testbed traffic generators

Weight files are git-ignored. Share them through a separate channel.

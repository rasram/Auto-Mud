# GNN installation reference fixture

This already-consumed 20-minute capture checks that the selected model package
loads and reproduces saved inference outputs. It contains 20 v4 graphs and
394 device/window records. Input graphs are about 1.07 MB; trimmed expected
scores/flags are about 101 KB. The manifest pins hashes and checkpoints.

From the repository root:

```bash
python -m ml check-model --bundle models/gnn --device cpu
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
```

Expected: 788 exact A/B flag matches, matching availability and score errors
within `1e-4` against the original saved CUDA predictions. No training occurs.
The fixture is not needed for live inference and is not an accuracy benchmark.
Do not use it for model selection/calibration. The full datasets remain private.

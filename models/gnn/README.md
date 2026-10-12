# Selected GNN model bundle

- `selected-a.pt`: New 2 native-clock/context A, including its saved scaler,
  residual references, A/B thresholds and embedded immutable B checkpoint.
- `frozen-b.pt`: original frozen B, supplied for exact integrity verification.
- `results.json`: only the selected model's saved evaluation results.
- `manifest.json`: paths, sizes, hashes and operating-point metadata.

These small checkpoints are explicitly eligible for Git. Both hashes match the
original artifacts. They require the current inference source; no training or
research dataset is needed. See the Linux guide and public fixture loading test.

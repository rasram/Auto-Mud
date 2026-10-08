# Training, evaluating, and integrating the detector

Current local setup and v2 dataset/model requirements: [LOCAL_WSL.md](LOCAL_WSL.md).
The local pipeline and monitoring command are documented there. Use fresh output directories.

## Before training

Complete the collection runbook and create `data/gnn/prepared/catalog.json`.
Run `python -m ml readiness --catalog ...` and inspect the report. Fix missing
partitions, unknown positive labels, or incomplete collection. Warnings about weak
coverage are not solved by duplicating rows.

All source and split choices must be declared before training. The clean first
stage accepts either measured `mininet` or synthetic `virtual_testbed` captures;
the latter remain marked `synthetic_training_model` in predictions and require
independent measured-capture validation before deployment. Scaling uses only
Stage-1 training data. Validation chooses training checkpoints; a separate normal
slice calibrates A/B thresholds. Test data is used only for final reporting.

Default partitions are:

| Partition | Purpose |
|---|---|
| `stage1_train` | Clean Mininet encoder/decoder/link training and scaler fitting |
| `stage1_val` | Clean Mininet convergence/checkpoint selection |
| `calibration` | Clean Mininet A/B threshold selection |
| `normal_test` | Untouched in-domain false-positive evaluation |
| `stage2_train` | Known active normal and malicious actors for Head C |
| `stage2_val` | Head C checkpoint, temperature and decision threshold |
| `stage2_test` | Untouched labeled sessions, including first-observation attacks |

Only `stage1_train` and `stage2_train` may reuse the same normal windows. Every
other overlap is rejected. Attack/control counterparts share a session ID; all
rows from that session go to one Stage-2 split. Public capture parts must be kept
together. Preparation records source/capture/graph hashes, and training verifies
prepared graph files have not changed.

## One command after data collection

```bash
python -m ml train-all \
  --catalog data/gnn/prepared/catalog.json \
  --out data/gnn/models/sage --epochs 100 --patience 10 --seed 42
```

This trains Stage 1, checks its gate, calibrates A/B, trains Head C, calibrates Head
C's output on validation, and evaluates normal/attack tests separately. The output
directory contains diagnostic and final checkpoints plus JSON reports.

## Separate stages

```bash
python -m ml train-stage1 --catalog data/gnn/prepared/catalog.json \
  --out data/gnn/models/stage1.pt
python -m ml calibrate --catalog data/gnn/prepared/catalog.json \
  --checkpoint data/gnn/models/stage1.pt --out data/gnn/models/calibrated.pt
python -m ml train-stage2 --catalog data/gnn/prepared/catalog.json \
  --checkpoint data/gnn/models/calibrated.pt --out data/gnn/models/model.pt
python -m ml evaluate --catalog data/gnn/prepared/catalog.json \
  --checkpoint data/gnn/models/model.pt --partition normal_test \
  --out data/gnn/models/normal-test.json
python -m ml evaluate --catalog data/gnn/prepared/catalog.json \
  --checkpoint data/gnn/models/model.pt --partition stage2_test \
  --out data/gnn/models/attack-test.json
```

## Architecture and losses

GraphSAGE uses two mean-aggregation layers, `99 -> 64 -> 16`, with ReLU between
layers. All neighbors are used at this household scale. No device-ID embedding is
learned. Reconstruction uses `16 -> 64 -> 38` and masked MSE on standardized traffic
features. Link expectedness uses a directed bilinear scorer and balanced BCE on
observed versus sampled nonrelationships. Each queried relationship is removed
from both directions of adjacency for its own encoder pass.

Negatives are sampled within a graph, excluding self-pairs, currently observed
relationships, and relationships seen in clean training. Graphs without available
positive/negative pairs skip link loss. Training requires validation examples with
both classes rather than accepting a meaningless link head.

Defaults: Adam 0.001, equal reconstruction/link weights, disconnected batches of
32 graphs with the original per-graph loss weighting, up to 100 epochs, patience
10, gradient norm
clip 5. Early stopping minimizes summed validation losses. The restored model must
beat a per-type mean reconstruction predictor and achieve balanced link BCE below
`log(2)` on held-out normal graphs. A failed gate saves a diagnostic checkpoint and
stops; inspect data coverage, degree diversity, scaling, and loss curves. Passing
this engineering gate is not evidence of useful attack detection.

Head C is `16 -> 32 -> 1`. Its encoder, decoder, and link weights are frozen; the
implementation asserts they remain byte-for-byte equal after training. Its
embedding pass masks historical destination novelty. Stage 1 includes occasional
masking of that input so the encoder sees this configuration. Head C therefore has
no dependency on a device's own clean history or profiling baseline.

Head C trains with source/class-balanced example weights. Validation BCE selects
the classifier checkpoint. Scalar temperature fitting and an F1-selected threshold
use only the declared validation set. These choices do not make a posterior
probability universally calibrated under deployment class-prevalence shift; report
validation composition and re-evaluate on representative deployment data.

## Calibration and output interpretation

Heads A/B thresholds are the 99th percentile of eligible, active, normal calibration
device scores. Link calibration uses the same per-device maximum incident anomaly
as inference. Types with fewer than 500 observations fall back to a stored pooled
threshold. Pooled thresholds are marked by absence of a per-type entry. Inactive
or unavailable devices are not treated as confidently normal; output fields are null
with a status. No incident edge also means link evidence is unavailable.

The model is static after training. Destination observation history is a causal
feature-extraction state, not automatic baseline retraining or policy permission.
Head C masks it. Do not incorporate attack windows into the Stage-1 scaler or
normal threshold calibration.

## Evaluation and ablations

Reports include support, positives, precision, recall, false-positive rate, PR-AUC,
ROC-AUC, and breakdowns by device type, source, attack family, and onset. AUC is null
for groups containing only one class. Detection latency measures attack interval
start to the end of the first flagged minute; undetected episodes remain null.
It does not include downstream enforcement latency.

Run the same predeclared catalog with `--architecture gcn` and `--architecture mlp`
to compare GCN and a node-only encoder. Keep seeds/threshold protocols consistent.
Use several model seeds when making comparative claims. The MLP is a graph-free
feature baseline, not a reproduction of any specific published paper's model.

Report public and Mininet performance separately. Public-only calibration/scaling
is not quietly mixed into Stage 1. Do not aggregate victim labels with actor labels.
For the cold-start claim, examine `onset=from_start` separately and use a new run
with no prior device history. Genuine unseen actor/device-type generalization needs
additional held-out devices beyond the initial three-actor scenario matrix.

## Inference and handoff

```bash
python -m ml predict --checkpoint data/gnn/models/model.pt \
  --graphs data/gnn/prepared/000-graphs.jsonl --out data/gnn/predictions.jsonl
```

Python integration:

```python
from ml.training.runtime import Predictor
predictor = Predictor("data/gnn/models/model.pt")
result = predictor.predict(finalized_graph_snapshot)
```

The upstream live adapter must emit finalized schema-compatible snapshots from
complete windows. Call `Predictor` once per window. Process the profiling deviation
score separately in the Decision Engine; this module does not produce a fused
score or authorize/block connections.

Checkpoints contain schema hash, feature-compatible architecture, weights, scaler
statistics, threshold/calibration metadata, dependency versions, seed/settings,
catalog hash, and training history. `torch.load` uses tensor-safe loading. Move the
complete checkpoint and the documentation together. Schema mismatch is an error;
do not reorder columns to make an incompatible tensor shape fit.

## CUDA training and progress

The trainer accepts `--device auto` (default), `--device cuda`, `--device cuda:0`,
or `--device cpu`. `cuda` explicitly fails if GPU computation is unavailable;
it does not silently fall back to CPU. CUDA-enabled PyTorch must be installed
in the interpreter used to run the command. The main project currently uses
the isolated `.venv-gnn` environment with PyTorch `2.14.1+cu130`.

```powershell
.\.venv-gnn\Scripts\python.exe -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
.\.venv-gnn\Scripts\python.exe -u scripts/train_ab.py --catalog data/gnn/virtual-normal-prepared/catalog.json --out data/gnn/models/my-new-ab-run --device cuda --epochs 100 --patience 10 --seed 42
```

`scripts/train_ab.py` requires a new output directory, checks A/B readiness,
trains the encoder and Heads A/B, checks the quality gate, calibrates thresholds,
and evaluates the untouched normal test. It writes `training.log`,
`run-status.json`, `readiness.json`, `stage1.pt`, `stage1.pt.report.json`,
`stage1.pt.progress.json`, `calibrated.pt`, and `normal-test.json`. An intermediate
`stage1.pt.best.pt` preserves the best weights during training; it is diagnostic
and is not a substitute for the final calibrated checkpoint.

Every epoch reports validation losses, duration, the estimate for the remaining
maximum epochs, and early-stopping progress. Completion records the GPU name,
CUDA runtime, PyTorch version, elapsed time, and peak CUDA tensor allocation.
The ETA can shorten when early stopping activates. These small graphs need
little GPU memory, so GPU utilization need not remain near 100 percent.

Batching preserves disconnected graph boundaries and per-graph loss weighting.
Link queries are still removed in both directions for their own scoring pass.
Tests compare batched losses and gradients against the original per-graph
calculation and exercise a CUDA forward/backward/optimizer step when available.

## Evaluate the frozen A/B model on a new attack/control catalog

The normal-only checkpoint is bound to its original training catalog. Use the
external adapter to evaluate `stage2_test` in a separately prepared matrix:

```powershell
.\.venv-gnn\Scripts\python.exe -u scripts/evaluate_ab.py --catalog data/gnn/virtual-prepared/catalog.json --training-catalog data/gnn/virtual-normal-prepared/catalog.json --checkpoint data/gnn/models/virtual-ab-cuda-20261007/calibrated.pt --out data/gnn/evaluation/my-new-evaluation/report.json --device cuda
```

Use a new report path. The adapter validates training-catalog provenance,
prepared graph hashes/schema, held-out session separation, duplicate captures,
known actor labels, complete windows, and paired controls. It preserves the
checkpoint, scaler and thresholds. It uses only `stage2_test`, not the matrix's
training or validation partitions, and does not train Head C.

The output contains overall confusion counts, accuracy, balanced accuracy,
precision, recall, F1, ROC-AUC, PR-AUC, scenario/onset/type breakdowns, paired
actor-only metrics, and episode detection/latency. Each head's coverage is
explicit: Head B has no score for a window without an observed incident
device-to-device edge. Its scored-window recall must be reported alongside
`population_recall`, which includes all known active malicious actor-windows.
Unscored windows are not silently classified as normal. Predictions are saved
beside the report as `report.predictions.jsonl`.

All peers and controls inherit their matched scenario for metric grouping,
but retain their own actor/normal labels. Normal victims can have anomalous
traffic during an attack, so compromised-actor false positives should also
be interpreted alongside control-only and paired-actor metrics. Thresholds
must not be tuned using this held-out test report; improvements need separate
development sessions and a newly reserved final test.

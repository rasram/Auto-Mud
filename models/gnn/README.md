# Supervised C deployment bundle

Version: `supervised-C-20261016`; manifest: `automud.gnn-bundle.v3`;
adapter: `supervised-direct.v1`. This is original C, seed 42, selected epoch 13,
of the C/E2 supervised family. E2 independently reproduced its binary benchmark
decisions; this release uses C's original bytes and C's own frozen cutoffs.

| File | Purpose |
|---|---|
| `detector.pt` | Joint supervised A/B checkpoint, no learned neighbor messages |
| `normalizer.json` | Frozen clean type/global feature statistics |
| `flow-profiles.json` | Frozen earlier-clean relationship counts and volume baselines |
| `thresholds.json` | C's frozen selection/clean-calibration cutoffs |
| `feature-contract.json` | Ordered raw descriptors, transforms and history contract |
| `results.json` | Consumed benchmark results and qualification limitations |
| `manifest.json` | Sizes/hashes of the six inputs and adapter/external contracts |

Checkpoint SHA-256:
`b89ed3d0496d02a33be5f02a5f5cd8938288943685f9e08d1cac360d149dabd7`.

A flags behavioral/affected-device evidence above `1.1537269353866577`.
B flags initiated-relationship evidence above `-0.2367836833000183`.
These are strict raw-logit comparisons, not calibrated probabilities. Quiet/
unavailable heads and B without an observed initiated relationship are null.
Both provenance checkpoint fields identify this single joint checkpoint.

Never deploy the checkpoint without its matching frozen assets or edit hashes
to bypass validation. The service does not refit profiles or thresholds.
See [Linux setup](../../docs/gnn/LINUX_PIPELINE_SETUP_20261012.md) and
[results](../../docs/gnn/MODEL_RESULTS.md). The old New 2 weights and screenshot
are no longer active public model artifacts.

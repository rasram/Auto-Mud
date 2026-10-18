# Original E1+Q deployment bundle

Version: `supervised-E1Q-20261018`; manifest: `automud.gnn-bundle.v3`;
adapter: `supervised-direct.v1`. Original E1, seed 42, selected epoch 5,
with its already-frozen lower-quartile (Q) cutoffs. No retraining or cutoff fitting.

| File | Purpose |
|---|---|
| `detector.pt` | Joint A/B checkpoint with directed learned incoming/outgoing messages and own-device GRU |
| `normalizer.json` | Unchanged frozen clean type/global statistics |
| `flow-profiles.json` | Unchanged frozen clean relationship/volume baselines |
| `thresholds.json` | Original E1's frozen Q cutoffs and calibration metadata |
| `feature-contract.json` | Unchanged ordered features, transforms and history contract |
| `results.json` | Previously measured consumed-benchmark results and limitations |
| `manifest.json` | Six exact file bindings and stable external/adapter contracts |

Checkpoint SHA-256:
`bf634ca9c98baf5a6507cf0882009c70630301adeb8b18d0a576751e42b5e5ad`.

Strict raw-logit cutoffs: A `0.7624336779117584`, B `4.921021908521652`.
Scores are neither calibrated probabilities nor MUD permissions. Idle/unavailable
heads and B without an observed initiated relationship remain null. Both
provenance fields identify the same checkpoint; `learned_neighbor_messages=true`,
`head_c_trained=false`. No T/teacher dependency is needed for inference.

The complete original C rollback is [models/gnn-c-20261016](../gnn-c-20261016/README.md),
with its own checkpoint and original cutoffs. Do not mix release assets or
overwrite directories referenced by a running service. Use the existing
stage/activate/rollback procedure in [the API guide](../../docs/gnn/LIVE_GNN_API.md).

This release changes the model and required loading adapter. The dataset,
preprocessing, service configuration and remaining pipeline stay unchanged.
Repository publication does not activate a teammate host. See
[results](../../docs/gnn/MODEL_RESULTS.md) and
[deployment checks](../../docs/gnn/DEPLOYMENT_VALIDATION.json).

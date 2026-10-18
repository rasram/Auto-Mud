# Supervised E1+Q teammate package

The current repository release is **original E1+Q**, `supervised-E1Q-20261018`:
seed 42, selected epoch 5, with its frozen lower-quartile cutoffs. It replaces C
as the default model. The feature projection, frozen profile/normalizer, service
configuration, external contracts and remaining pipeline are unchanged.

1. [Linux setup](LINUX_PIPELINE_SETUP_20261012.md): install, check the fixture and use the existing model lifecycle for a C-to-E1 upgrade.
2. [Pipeline handoff](LIVE_PIPELINE_HANDOFF_20261012.md): supplied ML work and the same 12 ordered teammate steps.
3. [Live API](LIVE_GNN_API.md): scores, retries, provenance, staging and rollback.
4. [Results](MODEL_RESULTS.md): saved benchmark results, A recall tradeoff and limitations.
5. [Deployment validation](DEPLOYMENT_VALIDATION.json): fresh E1 software, capture-replay and capacity checks.
6. [Schema](SCHEMA.md): stable telemetry and historical feature-hash compatibility.
7. [Model evolution](MODEL_EVOLUTION_20261013.md): E1+Q and retained C rollback.

E1 uses directed learned messages and own-device history. A/B logits are neither
probabilities nor MUD permissions; Head C remains untrained. The independent MUD
branch, finalizer, Decision Engine and Ryu work retain their existing ownership.
No teammate host was activated by publishing this package.

The small bundle/fixture are portable without private files. Original C remains
at `models/gnn-c-20261016` with its own fixture at `fixtures/gnn-c-20261016`.

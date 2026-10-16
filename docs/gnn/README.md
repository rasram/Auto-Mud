# Supervised C/E2 teammate package

The active release is **supervised C (E2 family)**, `supervised-C-20261016`.
It replaces self-supervised New 2 with a joint A/B detector, frozen clean
profiles, normalization and thresholds. The external live input/evidence
contracts stay unchanged. No training occurs in the service.

1. [Linux setup](LINUX_PIPELINE_SETUP_20261012.md): install, migrate old state, check the fixture, start C and reproduce capture acceptance.
2. [Pipeline handoff](LIVE_PIPELINE_HANDOFF_20261012.md): supplied ML work and 12 ordered teammate steps to complete the pipeline.
3. [Live API](LIVE_GNN_API.md): input/output meaning, retries, health, complete bundle replacement and rollback.
4. [Results and limitations](MODEL_RESULTS.md): consumed C benchmark results, including the later corpus's remaining B subgroup failures.
5. [Deployment validation](DEPLOYMENT_VALIDATION.json): supervised software, capture parity and capacity evidence.
6. [Schema](SCHEMA.md): external telemetry and the internal supervised adapter.
7. [Model evolution](MODEL_EVOLUTION_20261013.md): why the current joint supervised model differs from the previous package.

C uses graph-derived context and own-device history without learned neighbor
messages. A/B logits are not probabilities or MUD permissions. The independent
MUD branch, finalizer, Decision Engine and Ryu action app remain integration work.
The installation fixture and small frozen bundle are shareable; full datasets
and development history remain private.

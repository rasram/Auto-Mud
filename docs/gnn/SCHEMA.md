# Supervised live input, internal graphs and evidence

The stable public input is **`automud.live-window.v1`**:
canonical completed 60-second telemetry, stream identity, actual inventory/lease
version, UTC minute boundaries, watermark and capture health.
`configs/gnn/live/window.schema.json` is authoritative. Send it to
`POST /v1/windows`; teammates do not build features/tensors or supply labels.
See [the API](LIVE_GNN_API.md).

Load `network/zeek/automud-window.zeek` for directional minute IP-byte/packet
deltas and causal flow/outcome metadata. Ordinary connection lifetime totals
have different semantics. Acquisition/finalization must verify healthy silent
minutes and expose failed observations as unavailable.

Internally, the service uses **`automud.supervised-graph.v1`**,
adapter `supervised-direct.v1`. The feature order/hash is in
`configs/gnn/schemas/supervised/features.json` and `ml.supervised.schema`.
It extends the 50 v4 descriptors with seven frozen-profile/past-flow descriptors
and four current volume/fanout descriptors. There are 61 raw values/masks,
149 current model inputs, 15 strictly prior width-147 own-device vectors and
11 edge descriptors. E1 enables directed learned messages; retained C disables them.

Normalization preserves the original log transforms followed by clean
type/global standardization and `asinh`, with masks; it is not fitted live.
The current vector includes genuine UTC day phase, type/service context,
frozen baseline support and history count. Available histories stop at gaps,
unavailable observations or changed identity epochs. A changed frozen profile
clears model/profile history. Durable raw observations survive compatible
restarts and are normalized by the active bundle.

The installation fixture retains authentic captured-source clocks for exact
reproduction; live inputs supply actual UTC, not invented source provenance.
The finite-capture `build-graphs --bundle models/gnn` utility selects the
supervised adapter. Live continuity/deduplication belong to the HTTP service.
Old v3/v4 schemas are retained only for shared base operations/legacy migration.

The stable output is **`automud.gnn-evidence.v1`**:
`configs/gnn/live/evidence.schema.json`. It contains observation/stream/window/
inventory identity, health, history/reset information, bundle provenance and
household device rows. E1+Q does not emit external-service action targets.

A `behavioral_score/behavioral_flag` is behavioral/affected-device evidence.
B `link_anomaly/link_flag` is initiated-relationship evidence; it is null if
no observed initiated relationship exists. Both are raw supervised logits
with frozen global cutoffs and strict comparisons. `component_scores` is empty;
`profile_support.known_device` reports frozen baseline support.
Idle/unavailable heads remain null; null is not normal.

Envelope `head_c_trained=false`, `enforcement_action=null`,
`learning_regime=supervised_direct_detection` and
`learned_neighbor_messages=true` for E1+Q (false for retained C); per-device compromise probability is null.
Engineering observations must be excluded from enforcement. The Decision Engine
joins independent MUD evidence and owns response policy. Both checkpoint hash
fields identify the joint release checkpoint. The frozen schema hash retains its historical
`Detector(use_graph=False)` string; release architecture is validated separately. See the API for exact cutoffs/lifecycle rules.

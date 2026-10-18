# AutoMUD model evolution and current supervised release

Updated 18 October 2026. The current repository default is original **E1+Q**,
`supervised-E1Q-20261018`. Only the model bundle and required loading adapter
change in this upgrade. Service, transport, features, preprocessing, state
format and downstream integration remain unchanged.

## Original E1+Q

Original E1 seed 42, selected epoch 5, enables directed incoming/outgoing
sum/mean/count messages. It shares C's own-device encoder, 15-window causal GRU
and joint A/B layout. The 61 raw features still produce 149 current inputs and
15 prior vectors of width 147. No labels, future observations or run annotations
enter the projection. No teacher or T checkpoint is needed at runtime.

The checkpoint hash is
`bf634ca9c98baf5a6507cf0882009c70630301adeb8b18d0a576751e42b5e5ad`.
The existing lower-quartile cutoffs are A `0.7624336779117584` and
B `4.921021908521652`, using strict raw-logit comparisons. No training,
recalibration, dataset edits or new source allocations occur in this release.
Both consumed benchmarks pass their saved gates. The later A precision gain
over C has a small recall cost; T remains stronger. See [results](MODEL_RESULTS.md).

## Retained C/E2 release

Original C seed 42, selected epoch 13, `supervised-C-20261016`, remains an approved
rollback at `models/gnn-c-20261016` with its original cutoffs and fixture.
E2 independently reproduced C's binary benchmark decisions. C uses graph-derived
descriptors and own-device history with `use_graph=False`; its unused message
module keys remain for exact checkpoint loading. Its later benchmark has three
supported B subgroup failures. E1+Q does not inherit C's thresholds.

## Earlier residual models

New 2 used normal-traffic objectives, native-clock/context A residual scoring
and a separate frozen B. Its selected primary precision/recall were
A 83.3898%/89.8468%, B 99.6194%/99.7143%, on a different population/protocol.
Legacy v3/v4 helpers remain for base operations and explicit historical migration.
Those weights are not the default inference path.

## Stable integration

The adapter remains `supervised-direct.v1`, bundle manifest v3, with external
`automud.live-window.v1` / `automud.gnn-evidence.v1` contracts. E1 reports
`learned_neighbor_messages=true`; C reports false; both have `head_c_trained=false`.
The historical feature-schema hash includes the string `Detector(use_graph=False)`.
It remains unchanged because it identifies frozen feature projection, not the
release architecture. Approved-release bindings separately validate architecture,
checkpoint, frozen assets and cutoffs.

Use [Linux setup](LINUX_PIPELINE_SETUP_20261012.md), [the API](LIVE_GNN_API.md) and
[the ordered handoff](LIVE_PIPELINE_HANDOFF_20261012.md). The independent MUD,
Decision Engine and Ryu ownership and action policy are unchanged.

# AutoMUD model evolution and current supervised release

Updated 16 October 2026. The current shared release is **supervised C (E2
family)**, `supervised-C-20261016`. The filename is retained so existing links
continue to work. The earlier New 2 self-supervised package has been replaced.

## Earlier inference family

The initial graph detector used normal-traffic objectives and relationship
scoring. Later v4 work added receiver-side behavior and causal temporal context.
The selected New 2 model combined native-clock/context Head A, residual
references and a separate original frozen Head B. Its selected primary
precision/recall were A 83.3898%/89.8468%, B 99.6194%/99.7143%.
A missed its saved FPR/recall targets. Those results belong to the earlier
evaluation population and do not describe the current deployed checkpoint.

Legacy v3/v4 feature helpers and loaders remain for shared base operations
and explicit historical bundle migration. Their presence does not make the
old weights or residual scoring the live default.

## Current C/E2 supervised family

C directly learns two supervised detection outputs from metadata descriptors.
It uses 61 raw features: the 50 v4 descriptors, seven frozen-profile/past-flow
features and four current volume/fanout features. Exact clean normalization
and masks produce 149 current inputs; a GRU consumes 15 strictly prior
own-device vectors of width 147. Real UTC/native day phase and profile support
are retained. No class labels, run annotations or future observations enter
the feature projection.

C uses no learned neighbor messages. Its graph-derived fanout/context features
still depend on observed relationships. Unused message-module parameter keys
remain only to load the original checkpoint exactly. It is not evidence that
message passing improved performance.

The shipped checkpoint is original C, seed 42, selected epoch 13, SHA-256
`b89ed3d0496d02a33be5f02a5f5cd8938288943685f9e08d1cac360d149dabd7`.
E2 is an independent repeat with identical binary benchmark decisions, not a
second checkpoint combined at inference. C's own frozen operating point is
shipped unchanged. Both heads are now in one model; original frozen B is no
longer a runtime dependency.

## Meaning for integration and evaluation

The new internal adapter is `supervised-direct.v1`, bundle manifest v3.
The external `automud.live-window.v1` / `automud.gnn-evidence.v1` contracts
stay stable. The service owns new feature/history construction, profile-aware
resets, persistence and model swaps. Consumers must interpret scores as raw
supervised logits with saved cutoffs, preserve nulls and retire residual-score
assumptions.

C's earlier benchmark passes its saved checks. Its later aggregate precision/
population recall are A 99.1362%/99.4316%, B 99.9044%/99.5714%, but three
supported B subgroup checks fail. T was stronger in the completed comparison.
The benchmark populations differ from New 2's; these figures do not isolate
a gain caused by supervision, features or architecture.

See [results and limitations](MODEL_RESULTS.md) for the full current summary,
[Linux setup](LINUX_PIPELINE_SETUP_20261012.md) for migration and installation,
and [the ordered handoff](LIVE_PIPELINE_HANDOFF_20261012.md) for the remaining
integration steps. Training data and development records remain private and
are unnecessary for live inference.

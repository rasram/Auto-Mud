# Supervised E1+Q inference package

Owner: Jayan Subramanian. The default bundle is `supervised-E1Q-20261018`,
original E1 seed 42, selected epoch 5, with its frozen lower-quartile cutoffs. It supplies joint A/B logits with frozen
clean profiles, normalization and cutoffs, replacing the New 2 residual models.
Graph-derived context, directed learned incoming/outgoing messages and causal
own-device history contribute to scoring. Head C is untrained.

From the repository root in the qualified ML environment:

```bash
python -m ml check-model --bundle models/gnn --device cpu
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
python -m pytest ml/tests network/tests -q
python -m ml serve --config configs/gnn/live/service.json
```

The service accepts `automud.live-window.v1` and returns
`automud.gnn-evidence.v1`. It owns the 61-feature projection, actual UTC clock,
15-minute neural history, rolling observations, persistence and release swaps.
No labels, training stack or private imports are needed. The pipeline, service
configuration, feature projection and frozen preprocessing remain unchanged.
The approved C rollback is `models/gnn-c-20261016`; its fixture is
`fixtures/gnn-c-20261016`. Keep active release directories immutable and use
the existing stage/activate/rollback API for a running service.
`ml.live.client.Client` uses Python's standard library.

Use [Linux setup](../docs/gnn/LINUX_PIPELINE_SETUP_20261012.md),
[the live API](../docs/gnn/LIVE_GNN_API.md) and
[the ordered handoff](../docs/gnn/LIVE_PIPELINE_HANDOFF_20261012.md).
Teammates complete continuous acquisition/finalization, independent MUD
evidence, joins, Decision Engine and Ryu actions. Legacy v3/v4 residual code
remains available for explicit historical bundle migration and is not the
default supervised inference path.

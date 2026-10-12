# Selected GNN live inference package

Owner: Jayan Subramanian. This package supplies selected New 2 native-clock/context Head A and original frozen Head B, a live telemetry adapter, graph/history processing and the HTTP evidence service. Frozen weights, references and thresholds remain unchanged. There is no classifier, compromise probability or statistical-profiler fusion.

From the repository root in the qualified ML environment:

```bash
python -m ml check-model --bundle models/gnn --device cpu
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
python -m pytest ml/tests network/tests -q
python -m ml serve --config configs/gnn/live/service.json
```

The fixture checks loading and saved outputs; it is not training data or a live dependency. Full datasets and earlier development artifacts remain private and are not imported by this runtime. `ml.live.client.Client` provides the integration client using only the Python standard library.

Read [Linux setup](../docs/gnn/LINUX_PIPELINE_SETUP_20261012.md), [live API and swapping](../docs/gnn/LIVE_GNN_API.md), [pipeline handoff](../docs/gnn/LIVE_PIPELINE_HANDOFF_20261012.md) and [deployment validation](../docs/gnn/DEPLOYMENT_VALIDATION.json). Teammates supply sensor finalization/inventory/health and complete MUD/Decision Engine/Ryu integration; feature/history/tensor construction is supplied here. Compatible new bundles preserve the external telemetry/evidence interface.
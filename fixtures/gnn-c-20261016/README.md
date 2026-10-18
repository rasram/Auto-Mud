# Consumed supervised installation reference

Nine already-consumed C graphs (normal, cold lateral and continuous lateral),
with exact causal prior graphs, expected outputs and a hash manifest.
There are 108 household device/window records and 216 A/B flag checks.
The original C CPU outputs reproduce with zero maximum absolute score error;
the portability tolerance is `1e-4`.

```bash
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
```

This verifies model loading, frozen feature/tensor projection and saved outputs.
It is not training data, new evaluation or a reproduction of aggregate metrics.
No full dataset or private script is required. Do not tune on this fixture.
Live operation uses observed UTC windows and its own state, not these graphs.

# E1+Q installation reference

Nine previously consumed graphs, 108 household records and 216 flag checks.
`graphs.jsonl` is byte-identical to the C installation input, including exact
causal priors. Only expected model outputs and checkpoint bindings change.
Expected logits come from saved original E1 benchmark predictions; flags use
the already-frozen Q cutoffs. Nothing is fitted or added to the research dataset.

```bash
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
python -m ml check-fixture --bundle models/gnn-c-20261016 --fixture fixtures/gnn-c-20261016 --device cpu
```

This checks installation parity within `1e-4` CPU logit error, with exact flags,
statuses and opportunities. It is not fresh accuracy evidence. C's original
complete fixture remains in `fixtures/gnn-c-20261016` for rollback verification.

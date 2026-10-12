# Causal graph construction

`build.py` and `context.py` construct minute graphs from canonical telemetry.
`ml.ab_targets.graphs.build_v4` adds the receiver features required by the selected
Head A and preserves the v3 projection required by frozen Head B.
Use real inventory bindings, completed 60-second windows and strictly prior history.
`ml.live.graphs.StreamingGraph` supplies rolling state and observation health across windows; `ml.live.engine.LiveEngine` owns persistence and deduplication.

# Selected GNN input and output

The public live input is **`automud.live-window.v1`**: canonical completed 60-second telemetry, run/session/sensor identity, inventory/lease version, genuine UTC timestamps, watermark and capture health. It is defined in `configs/gnn/live/window.schema.json`. Teammates send it to `POST /v1/windows`; they do not construct feature arrays or model tensors. See [the live API](LIVE_GNN_API.md) for field meaning, limits, retries and examples.

Use `network/zeek/automud-window.zeek`, which emits directional minute IP-byte/packet deltas and causal flow/outcome metadata. Ordinary connection lifetime totals are unsuitable. Continuous acquisition/finalization belongs to integration; healthy silent minutes require genuine capture progress. A missing/failed observation is unavailable, not a zero-activity observation.

Internally, `ml.live.graphs.StreamingGraph` builds **`automud.graph.v4`** with node features/masks, directed edges, availability and strictly prior temporal histories. Feature dimensions/order/hash are in `ml.ab_targets.schema` and `configs/gnn/schemas/v4/`. Original frozen B uses the preserved v3 projection. The ML adapter owns these details. Live UTC clocks use an internally validated `automud.observation-clock.v1` tag and preserve real hour/day meaning; legacy captured-native provenance remains supported for the public fixture. No invented source intervals or future capture bounds are needed from teammates.

The offline `build-graphs` command remains a finite-capture utility. Production streaming history, deduplication, outage/gap/identity resets and persistence are provided by the live service, not the offline utility.

Output is **`automud.gnn-evidence.v1`**, defined in `configs/gnn/live/evidence.schema.json`. It includes stream/window/inventory identity, observation ID/kind, bundle/checkpoint provenance, sensor health, history/reset information and devices with:

- Identity/type and `status` (`ok`, `inactive`, `unavailable`).
- A `behavioral_score/behavioral_flag` and B `link_anomaly/link_flag`.
- Component scores, saved threshold/calibration scope, fallback and unscored reasons.
- Prior history/warm-up information; `compromised_probability=null`.

Envelope `head_c_trained=false` and `enforcement_action=null`. Scores are not probabilities and A/B scales differ. Null means unscored. Engineering observations are explicitly labeled and excluded from enforcement. The Decision Engine joins matching independent MUD evidence and chooses actions. External-service graph nodes are context, not household response targets.

Compatible bundle replacements preserve the external telemetry/evidence interface. A different internal feature or architecture family requires an ML adapter update, without transferring tensor construction to teammates.
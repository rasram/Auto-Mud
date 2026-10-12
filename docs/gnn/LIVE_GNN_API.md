# Live GNN API and integration contract

The supplied service owns graph construction, feature order, normalization, UTC clock conversion, temporal history and frozen A/B scoring. The orchestrator supplies completed sensor observations and consumes evidence. No full dataset, attack labels or prepared tensors are needed for live operation. Start it using [Linux setup](LINUX_PIPELINE_SETUP_20261012.md); ownership is in [the handoff](LIVE_PIPELINE_HANDOFF_20261012.md).

## 1. Endpoints and transport

Default address: `http://127.0.0.1:8001`. Use JSON bodies and `Content-Type: application/json`. If configured, send `Authorization: Bearer <token>`. The standard-library Python client is `ml.live.client.Client`; it does not import Torch/PyG.

| Method / route | Purpose | Body / authorization |
|---|---|---|
| GET `/healthz` | Model integrity/readiness, per-stream freshness/health, statistics | API token if configured |
| GET `/readyz` | 200 if the model/engine is ready, otherwise 503 | API token if configured |
| GET `/v1/model` | Active version, bundle ID and checkpoint hashes | API token if configured |
| GET `/v1/contracts` | Input and output JSON schemas | API token if configured |
| POST `/v1/windows` | Accept one completed minute and return evidence | Window envelope; API token if configured |
| POST `/v1/models/stage` | Validate and forward-probe a candidate without activating | `{"bundle":"models/gnn-next"}`; admin token |
| POST `/v1/models/activate` | Activate a staged candidate between completed windows | `{"bundle_id":"<candidate ID>"}`; admin token |
| POST `/v1/models/rollback` | Restore the named previous bundle | `{"bundle_id":"<previous ID>"}`; admin token |
| POST `/v1/sessions/reset` | Retire/reset a stream; its next window starts cold | `{"run_id":"...","session_id":"...","sensor_id":"..."}`; admin token |

API and administrator tokens are separate environment variables, defaulting to `AUTOMUD_GNN_API_TOKEN` and `AUTOMUD_GNN_ADMIN_TOKEN`. No admin token means admin endpoints are disabled (403). Non-loopback binding requires an API token. The service provides plain HTTP: use a trusted lab network or a TLS proxy for remote transport. Keep administrator access with the deployment owner.

## 2. Input: completed sensor window

Authoritative schema: `configs/gnn/live/window.schema.json`, version **`automud.live-window.v1`**. All envelope fields below are required; unknown fields and labels are rejected.

| Field | Meaning |
|---|---|
| `schema_version` | `automud.live-window.v1` |
| `observation_kind` | `live` for genuine live observations; `engineering` for examples, synthetic traffic and acceptance tests |
| `run_id`, `session_id`, `sensor_id` | Stable stream identity; a fresh independent run/session starts fresh history |
| `inventory_version` | Version of the actual inventory used for this observation |
| `window_start`, `window_end` | Integer UTC Unix seconds; start divisible by 60, end=start+60; half-open interval `[start,end)` |
| `watermark` | Sensor progress in UTC seconds; must reach end for a complete window |
| `inventory` | Actual devices, stable IDs/types and time-valid MAC/IP bindings |
| `health` | Observation completeness, sensor/clock health, interval drops and unavailable devices |
| `telemetry` | Canonical minute rows from `network/zeek/automud-window.zeek`; an empty list is valid |

Inventory entries require `device_id`, `device_type`, `addresses`; optional `mac`. Each address is `{"ip":"10.0.0.11","start":<lease start UTC>,"end":null}` or has an actual finite lease end. Use the genuine lease start consistently, not a new invented lease each minute. Open leases are clipped internally to the already-observed interval. Types are validated against `ml.schema.TYPES` (use `unknown` if genuinely unknown); household inventory cannot use `external_service`. Missing/expired bindings and ownership changes inside a minute make the affected device unavailable. Simultaneously ambiguous IP ownership is rejected. Preserve actual IDs; do not rename devices to borrow calibration.

Health requires:

```json
{
  "complete": true,
  "sensor_healthy": true,
  "clock_synchronized": true,
  "capture_drops": 0,
  "unavailable_device_ids": []
}
```

These values must come from capture/finalization checks. `capture_drops` is the interval count, not an ever-increasing lifetime total; null means unknown. Incomplete capture, unhealthy sensor, unsynchronized clocks or unknown/nonzero drops make the whole minute unavailable. A known device outage goes in `unavailable_device_ids`. Such valid bad windows return 200 with explicit unavailable/null evidence, advancing the timeline without inventing observations.

Each telemetry row requires `schema_version` (canonical telemetry `automud.graph.v1/v2/v3`), `window_start`, `uid`, `orig_h`, `resp_h`, `proto`, `flow_start`, directional `orig_ip_bytes/resp_ip_bytes`, `orig_pkts/resp_pkts`, `observed_duration`, `established`, `failed`, and `new_flow`. Ports, MACs and `tcp_syn_observed` are optional according to the schema. Retain them when available. One UID per minute is allowed; the same ongoing UID may recur in subsequent minutes. Direction is initiator to responder; counts are IP-packet/byte deltas in that minute. Duration and outcome fields must be causal, as emitted by the project policy. Ordinary `conn.log` lifetime totals are unsuitable.

The sensor finalizer belongs to integration: buffer rows by UTC minute, wait for trustworthy sensor progress, attach inventory/health, and send ordered windows. Zeek packet arrival alone cannot close healthy silent minutes. Supply empty minutes only when observation continued successfully; send bad health or leave an explicit gap during an outage. The service does not read packets, discover inventory or independently measure capture loss.

## 3. Client example and retry rules

The integration process can use this client with only Python's standard library:

```python
import json
import os
from ml.live.client import Client

client = Client('http://127.0.0.1:8001',
                token=os.environ.get('AUTOMUD_GNN_API_TOKEN'),
                timeout=30, retries=2)
# The finalizer writes this exact canonical envelope; no ML tensors are supplied.
with open('completed-window.json', encoding='utf-8') as source:
    window = json.load(source)
evidence = client.submit(window)
# Join only matching device/window/identity evidence from the independent MUD branch.
```

Persist an outbound window until acceptance and retry the same payload after a timeout or transient capacity/503 response. Canonical sorting of inventory, addresses and UIDs makes reordered equivalent requests match. Changed content for an accepted minute is a conflict, not a correction. The default cache retains eight windows per stream; older retries are rejected instead of rescored. Accepted responses/history survive a restart. Stop sending a stream before administratively resetting it; reset is not automatically retried by the client.

| Status | Meaning / handling |
|---|---|
| 200 | Accepted observation or identical cached replay; inspect device and sensor health |
| 401 / 403 | Missing/wrong token or administrator operations disabled |
| 409 | Conflicting duplicate or out-of-order/evicted minute; investigate, do not change the payload to bypass it |
| 413 / 415 / 422 | Oversized request, wrong content type or invalid schema/semantics; fix acquisition/configuration |
| 429 | Stream/state/feature capacity limit; retire an unused stream or review sizing |
| 503 | Busy, model integrity, processing or persistence problem; inspect health and retry the same unaccepted window |

Identical accepted retries return the original JSON and `X-AutoMUD-Replay: true`, including the original model version. Activation and targeted rollback are also retry-safe. Staging is validation-only and can be repeated before activation; staging an already-active bundle is rejected. The client retries GETs, windows, staging, activation and targeted rollback on transient errors; it does not retry reset automatically.

## 4. Evidence and decision integration

Authoritative schema: `configs/gnn/live/evidence.schema.json`, version **`automud.gnn-evidence.v1`**. Output carries run/session/sensor/window/inventory identity, `observation_id`, `observation_kind`, bundle/checkpoint provenance, sensor health, state-reset information and a `devices` array.

For each device:

- Head A: `behavioral_score`, `behavioral_flag`.
- Head B: `link_anomaly`, `link_flag` (initiated relationships).
- `status`: `ok`, `inactive` (healthy but quiet) or `unavailable`.
- `component_scores`, saved `calibration_scope` including threshold/scope/fallback, and `unscored_reasons`.
- `history`: prior window count, observed age and `fully_warmed` (15 prior neural windows plus at least one hour of observed rolling history).
- `compromised_probability=null`; envelope `head_c_trained=false` and `enforcement_action=null`.

A and B have distinct scales; use their saved flags/threshold provenance, not a fabricated shared probability. Null means unscored, not normal. A healthy idle device can have unscored heads; inspect each head's reason and availability. Cold-start evidence may be produced with shorter histories and is marked accordingly. Gaps reset all stream history; binding changes reset the affected device; outages clear affected histories. The first hour after a reset lacks fully warmed rolling history.

External-service graph nodes may appear in evidence. Only inventory devices are household action targets. The Decision Engine must preserve initiator context and current binding, exclude `observation_kind=engineering`, join matching GNN/MUD evidence, and choose a response under its own policy. A high receiving-device score does not prove that device initiated an attack. GNN anomalies do not override MUD permission failures.

`/readyz` establishes model/service readiness, not sensor readiness. `/healthz` exposes each stream's `stale` and `observation_healthy`; default staleness is 180 seconds after its last window end. The orchestrator must check freshness/health and branch timeouts. `health.processing_seconds` measures graph/scoring work before persistence; capacity reports measure the complete HTTP request including state saves. Neither measures packet-to-OVS response latency.

## 5. Safe model replacement and rollback

Jayan exports a separately trained/evaluated compatible checkpoint; export does not train, refit thresholds or measure accuracy:

```bash
python -m ml export-bundle --checkpoint /path/to/new-a.pt \
  --frozen-b models/gnn/frozen-b.pt --out models/gnn-next \
  --version new-a-release-1 --results /path/to/evaluated-results.json
python -m ml check-model --bundle models/gnn-next --allow-candidate --device cpu
```

Use a fresh output directory. The v2 manifest binds filenames/sizes/hashes, external contracts, graph hash and `v4-residual-native.v1` adapter. The A checkpoint's embedded B must equal the supplied standalone B. The currently supplied adapter supports this compatible v4 native-clock/residual family; different feature or architecture families need an internal ML adapter update, while the external contracts remain stable. A new model does not reproduce the old model's fixture outputs: use the old fixture for the baseline installation and a separately evaluated candidate's own acceptance evidence.

Deploy the entire bundle under an allowed root (`models/` by default), readable by the service. Keep files immutable after export. Record the current ID, stage, activate, and retain the previous ID for rollback:

```python
import os
from ml.live.client import Client

api = Client(token=os.environ.get('AUTOMUD_GNN_API_TOKEN'))
admin = Client(token=os.environ['AUTOMUD_GNN_ADMIN_TOKEN'])
previous_id = api.call('/v1/model')['bundle_id']
staged = admin.call('/v1/models/stage', {'bundle': 'models/gnn-next'})
candidate_id = staged['model']['bundle_id']
admin.call('/v1/models/activate', {'bundle_id': candidate_id})
# If deployment checks require rollback, name the recorded target explicitly:
admin.call('/v1/models/rollback', {'bundle_id': previous_id})
```

Staging does not change the active model. Hash/schema/weight/normalizer checks and a forward probe precede activation. They establish software compatibility, not predictive quality. Activation/rollback wait for current processing to finish and durably save the model pointer. Raw feature histories are preserved and re-normalized by the active bundle, rather than reusing old model hidden states. Active/previous versions and history are restored after restart; a merely staged candidate is not persisted and must be staged again. Keep the active and previous directories intact. Reset/new sessions require cold-start handling; never edit the durable state to bypass model checks.

## 6. Capacity and operation

Defaults: CPU, one Torch thread, eight streams, eight HTTP connections, 64 inventory devices/window, 5,000 telemetry rows/window, 4 MiB request, 16 MiB state, 4,096 retained peer entries/device, eight cached windows, 15-second body timeout. Scoring/state transitions are serialized. One service owns one state file; a second instance sharing it is rejected. These are bounds, not an arbitrary-size deployment guarantee. Monitor health statistics and the orchestrator's queue age; persist/back off rather than discard minutes silently.

Configuration paths resolve against `project_root` in `configs/gnn/live/service.json`; its default `../../..` resolves to the repository. State/model file paths are host-specific: if relocating a deployment, start a new session or migrate paths deliberately and revalidate. Back up state and immutable bundle directories together while the service is stopped. Do not copy the model developer's private dataset or virtual environment.
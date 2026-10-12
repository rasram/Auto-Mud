# AutoMUD GNN-only pipeline handoff

The ML deployment work in section 3 is complete. Teammates can run the supplied GNN service and finish the remaining pipeline without writing model features, tensor conversion or history code. Jayan can continue training and deliver compatible replacement bundles through the same input/output interface.

The baseline is the **New 2 native-clock/context Head A and original frozen Head B** in the screenshot. Weights, preprocessing, reference statistics and saved thresholds are unchanged. Read [selected results](MODEL_RESULTS.md), [Linux setup](LINUX_PIPELINE_SETUP_20261012.md) and [live API](LIVE_GNN_API.md).

## 1. Architecture and current readiness

```text
Live Mininet -> Open vSwitch -> mirror -> Zeek + interval finalizer
                                                |
                           completed canonical 60-second windows
                                                |
                        +-----------------------+------------------+
                        |                                          |
             supplied live GNN service                         MUD engine
             graph/history -> swappable A/B                   policy evidence
                        +-----------------------+------------------+
                                                |
                                         Decision Engine
                                                |
                                      Ryu OpenFlow controller
                                                |
                                     Open vSwitch response
```

The service accepts telemetry and inventory over HTTP and owns feature construction internally. It loads once, persists history, reports health and returns separate A/B scores. Neo4j is optional storage. Scores are not probabilities; Head C is untrained. No statistical-profiler/hybrid decisions are emitted. The orchestrator, Decision Engine and AutoMUD Ryu action app remain teammate work. Existing collection launchers use standalone OVS.

## 2. Required package and datasets

| Deliverable | Needed for operation? | Supplied here? |
|---|---|---|
| Weights, scaler, references and thresholds | Yes | `models/gnn/` |
| Live graph/clock/history adapter and HTTP inference | Yes | `ml/live/`, `ml/clock.py`, `ml/inference.py` |
| Schemas and service configuration | Yes | `configs/gnn/live/` |
| Sensor windows and honest capture health | Yes | Team supplies acquisition/finalizer; Zeek policy supplied |
| MUD, Decision Engine and SDN enforcement | Yes | Team finishes/qualifies them |
| Small reference fixture | Installation test | `fixtures/gnn/` |
| Full training/evaluation dataset | No | Private, excluded from Git |

```bash
python -m ml check-model --bundle models/gnn --device cpu
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
```

Expected fixture: 20 graphs, 394 records, 788 matching A/B flags and score differences at most `1e-4`. It checks loading and reproduction, not new accuracy. Mininet supplies live observations. Full data is needed only for training or reproducing aggregate research results; it stays private.

## 3. ML deployment work — completed

| Requirement | Delivered and checked |
|---|---|
| Frozen telemetry/evidence contracts | `automud.live-window.v1` and `automud.gnn-evidence.v1` schemas, HTTP API and standard-library client |
| Genuine clock and identity | UTC minute boundaries and validated stable IDs/MAC/IP leases; no invented replay dates, future capture bounds or labels |
| Stateful streaming wrapper | Rolling features, strictly prior history, duplicate caching, gap/identity/outage resets and bounded durable state with exclusive ownership |
| Runtime and operations | Pinned top-level dependencies, recorded Linux/WSL environment, launcher, systemd template, health/readiness and measured capacity |
| Bundle swapping and rollback | Compatible v2 export, validation/forward probe before activation, activation between windows, durable versions and targeted retry-safe rollback |
| Live acceptance | Real isolated Mininet/OVS capture through Zeek and HTTP; normal connections/closed-port probes, exact offline/live feature and score parity, retries/restart/swap |

All **45 regression tests pass**, covering 80 minutes of offline/streaming feature parity, silence, loss, unknown identities, invalid inputs, persistence failure, concurrent activation and service startup/shutdown. The consumed model fixture still reproduces within the saved tolerance.

The 12-device/60-window CPU workload measured approximately **64 ms median, 72 ms p95 and 156 ms maximum** HTTP processing, including state saves. Peak process RSS was about **756 MiB**, with existing CUDA-enabled Torch used on CPU. This is a capacity probe, not detection accuracy or full network latency. The real capture reported zero drops, observed all 16 controlled closed-port attempts and had zero live/offline score error. See [deployment validation](DEPLOYMENT_VALIDATION.json).

Jayan's recurring responsibility is training, separate model evaluation and compatible bundle export. No further training is required to integrate this baseline. A different architecture/feature family may need a new internal ML adapter; teammates continue using the external contracts. Fresh native-host installation and full controller/enforcement acceptance remain team deployment tasks; the WSL check does not establish those.

## 4. Teammate responsibilities and completion sequence

| Owner | Remaining work |
|---|---|
| Sarveshwar Balu — MUD/profiling | Permission evidence, policy versions and shared identity mapping |
| Anand Mahadev — network/SDN | Controller-managed Mininet/OVS, inventory, bidirectional mirror, sensor health, qualified Ryu environment and action app |
| Rashwanth Ram — integration | Zeek interval finalizer/client, timed evidence join, Decision Engine, action transport, events/explanations/dashboard |
| All owners | End-to-end acceptance, actual action effect, timing and recovery |

1. Install the current package, pass the fixture and launch the GNN service using the Linux guide. Cloning the old commit alone omits this uncommitted package.
2. Create controller-managed Mininet with OpenFlow 1.3, MUD base flows and a dedicated mirror. Capture inside the sensor namespace and verify both directions.
3. Finalize each UTC minute using the project Zeek policy. Maintain actual IDs, types, MAC/IP leases, watermark and capture health. Send ordered windows to `POST /v1/windows`, including healthy empty minutes and explicit bad minutes. Absence of traffic does not establish sensor health.
4. Feed corresponding observations to MUD. Join by run/session/sensor/device/window and inventory version, with explicit branch timeouts/unavailability. Keep engineering examples out of enforcement.
5. Run the Decision Engine in observation mode. Configure response tiers, cooldowns and TTLs using saved flags and each branch's distinct score semantics. Preserve null, inactive, warm-up and stale states.
6. Implement the Ryu action endpoint and demonstrate a scoped rule, actual traffic effect, expiry and recovery. Then connect events and dashboard.

MUD permissions are independent of anomaly evidence. A low GNN score does not permit a forbidden connection. A high recipient score does not identify the initiating attacker. Retain initiator/binding context for response selection. Rate limiting needs meters/QoS; VLAN quarantine needs configured connectivity.

## 5. Stable service interface and replacement

Input is canonical completed telemetry plus inventory, not a teammate-maintained feature array. Output is versioned evidence with identity/status, A `behavioral_score/behavioral_flag`, B `link_anomaly/link_flag`, calibration scope, unscored reasons, history, health and bundle/checkpoint provenance. `compromised_probability` and `enforcement_action` are null. The [API guide](LIVE_GNN_API.md) defines endpoints, retry behavior, field meaning and replacement commands.

The v4 adapter accepts compatible exported bundles. Stage validates schema, weights, embedded B, normalizer and hashes and performs a forward probe; it does not establish candidate accuracy. Activate an independently evaluated release. Keep both bundle directories intact for rollback. Raw feature history is re-normalized by the active model. Replayed accepted windows retain their original version and outputs.

## 6. Full-pipeline acceptance and limitations

Ryu actions need an idempotent decision ID, validated current binding, switch/DPID, scoped match, parameters, priority/cookie, TTL, reason and evidence reference. Return accepted/rejected/installed status and errors. Verify barriers, flow tables, counters and actual traffic effect.

On its own host the team must test evidence joins, normal/controlled attack traffic, cold start, silence, drops, identity changes, branch outages, duplicates, restart, enforcement/expiry and rollback. Supplied ML checks do not test MUD policy or Ryu action correctness.

Measure packet onset, window close, evidence ready, engine decision, controller acknowledgement and confirmed traffic effect separately. Sixty-second windows impose detection delay. Selected evaluation precision/recall remains A **83.39%/89.85%**, B **99.62%/99.71%**. A misses the saved 5% FPR cap and 90% recall target. Live accuracy on new traffic remains unverified. Report GNN, MUD and action outcomes separately while training improvements continue.
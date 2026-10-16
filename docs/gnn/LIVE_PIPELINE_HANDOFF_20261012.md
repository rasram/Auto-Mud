# AutoMUD supervised C/E2 live pipeline handoff

Updated 16 October 2026. The shared pipeline now uses **supervised C, the E2
family**, in `models/gnn/` (version `supervised-C-20261016`). The deployed
checkpoint is original C, unchanged; E2 is its repeat, not a second live model.
This replaces New 2's self-supervised A and separate frozen B.

The ML service, supervised feature/history adapter, frozen assets, installation
fixture and software acceptance are supplied. Teammates complete the sensor
finalizer, independent MUD branch, orchestrator, Decision Engine and Ryu action
app by following the steps below. Full datasets and training are unnecessary
for integration. Read [Linux setup](LINUX_PIPELINE_SETUP_20261012.md) first.

## What is supplied and how evidence flows

```text
Mininet -> controller-managed OVS -> dedicated mirror -> Zeek + interval finalizer
                                                               |
                                         completed UTC 60-second observations
                                                               |
                                +------------------------------+----------+
                                |                                         |
                 supplied supervised C service                       MUD engine
                 features/history -> joint A/B                    permission evidence
                                +-------------------+---------------------+
                                                    |
                                          timed join + Decision Engine
                                                    |
                                            Ryu action endpoint
                                                    |
                                        OVS rule -> measured traffic effect
```

Only the C branch is a supervised detector. The MUD branch evaluates permissions
independently. The Decision Engine owns actions. Neo4j is optional event storage.

| ML deliverable | Supplied implementation |
|---|---|
| Frozen release | Joint `detector.pt`, clean profile, normalizer, cutoffs, feature contract, results and hash manifest |
| Stable integration | `automud.live-window.v1` input, `automud.gnn-evidence.v1` output, HTTP and standard-library client |
| Supervised adaptation | 61 raw features, exact normalization/clock, 149 current inputs, 15 strictly prior own-device vectors of width 147 |
| Live state | Ordered minutes, health/identity/gap resets, bounded history, durable save/restart, deduplication |
| Model lifecycle | Complete supervised bundle export, validation/probe, serialized activation, profile-aware history resets and targeted rollback |
| Qualification | Consumed reference reproduction, regression, independent archived feature/tensor parity, Mininet/Zeek/API acceptance and CPU capacity report |

The model uses graph-derived counts and context, **without learned neighbor
messages**. A reports behavioral/affected-device evidence; B reports initiated
relationship evidence. Both are raw logits, not probabilities. Both checkpoint
hash fields refer to the same joint model. There is no trained Head C,
compromise probability, attack-family prediction or automatic enforcement.

Installation checks:

```bash
python -m ml check-model --bundle models/gnn --device cpu
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
python -m pytest ml/tests network/tests -q
```

Expected: six verified files; fixture 9 graphs / 108 household records / 216
matching flags; 52 passing tests. Reference CPU logits reproduced exactly.
An independent 80-minute comparison also matched archived batch features,
masks, edges, tensors and logits exactly, including a state save/restore.
[Deployment validation](DEPLOYMENT_VALIDATION.json) records the new release's
capture and capacity results. These checks establish software compatibility;
fresh native-host acceptance and full MUD/Ryu enforcement remain team work.

The release's 12-device/60-window CPU capacity probe measured approximately
141 ms median, 189 ms p95 and 287 ms maximum HTTP processing including durable
state saves, with about 748 MiB peak process RSS. Real isolated capture
acceptance observed all 16 controlled closed-port rows with zero drops and
zero live/offline score error. These are engineering measurements, not attack
accuracy or packet-to-enforcement latency.

## Remaining work: follow these steps in order

Each step states the owner, actions and completion check. Keep the collected
configurations/logs/reports together as the deployment acceptance record.

### Step 1. Agree the inventory and deployment configuration

**Owners: Anand Mahadev + Rashwanth Ram; Sarveshwar Balu reviews MUD mapping.**

Use `network/testbed/topology-supervised.json` and
`configs/gnn/live/inventory.example.json` for the authored 12-device cohort.
The older default topology has different devices and IP assignments.
Populate actual stable IDs, types, MACs, UTC lease starts/ends and an inventory
version. Do not use the example as fabricated lease evidence or rename an
unrelated device to a known model identity.

Record host paths, sensor interface/ID, UTC synchronization, switch DPID,
controller address/port, ML/MUD routes, timeouts, policy versions, state paths
and action TTLs. Make traffic generators and MUD policies use that same map.

**Complete when:** each IP/MAC at a minute resolves to one intended device;
the controller's current port/binding map and both evidence branches agree.
Unknown devices retain honest identities and missing-profile support.

### Step 2. Qualify the Ryu environment and build the live testbed launcher

**Owner: Anand.**

Follow Linux setup steps 2 and 9. Pin a working controller environment/image
separately from ML. Run `ryu-manager --help`, start the selected app, and create
Mininet using `OVSSwitch`/`RemoteController` with OpenFlow 1.3.
Choose and document fail mode, baseline forwarding and controller port.

Extend or add the live launcher deliberately: existing `run_full_topology.py`
and collection tools use standalone OVS and do not supply the finished Ryu app.
Use the supervised topology explicitly and prepare matching traffic inputs.
Do not claim a learning-switch connectivity check implements MUD enforcement.

**Complete when:** Ryu sees the intended DPID, OVS reports a connected controller,
normal baseline traffic works and the configured flows appear in the actual
switch table. Save versions, startup commands and flow dumps.

### Step 3. Connect the dedicated sensor and verify observation quality

**Owner: Anand.**

Add a dedicated sensor link/port, configure an idempotent bidirectional OVS
mirror, and run Zeek inside that sensor host namespace. Load
`network/zeek/automud-window.zeek` using absolute paths. Verify both directions,
minute byte/packet deltas, ongoing connections, failed connection attempts,
offloads, capture drops and absence of duplicate mirror copies.

Reproduce Linux setup step 8's isolated packet-to-API acceptance on this host
before connecting the whole system. Its bridge `amgnn0` is independent of the
deployment switch; use fresh output paths.

**Complete when:** genuine controlled packets appear once with correct direction
and causal fields; acceptance reports pass with zero drops and matching model
outputs. Record the real interface and loss-measurement method.

### Step 4. Implement the continuous UTC minute finalizer and sender

**Owner: Rashwanth; Anand supplies sensor health and bindings.**

Buffer canonical Zeek rows by `[window_start, window_start+60)`. Finalize only
after trustworthy sensor progress/watermark reaches the end. Resolve the actual
inventory for that interval, attach interval capture drops, sensor/clock health
and device outages, then persist the complete outgoing envelope before sending.

Use `automud.live-window.v1`; fields and examples are in
[the API](LIVE_GNN_API.md#2-input-completed-sensor-window).
Include healthy silent minutes as `telemetry=[]` only if capture continued.
Send unhealthy/incomplete minutes with honest bad health; never fill outages
with benign zeros. Handle startup partial minutes and final shutdown explicitly.
Do not send labels, future timestamps or manually constructed features.

Use `ml.live.client.Client` or `python -m ml submit-window`. Keep each
unaccepted payload until successful acknowledgement. Retry that exact payload
after transient errors; do not “fix” an accepted minute's content.

**Complete when:** a multi-minute run includes traffic, silence and a sensor
interruption with correctly ordered windows, watermarks, null/unavailable
evidence and identical retry responses. The queue's age/backlog is observable.

### Step 5. Start C and integrate the supervised evidence fields

**Owner: Rashwanth; Jayan owns model releases.**

Follow Linux setup steps 4–7. Existing New 2 installations must first stop,
back up the old bundle/state together and use the new
`tmp/gnn-live-supervised/state.json`. Do not restore old residual-model state
against overwritten files. Start the service as an ordinary user and confirm
`/readyz`, `/v1/model` and the consumed fixture.

Use returned flags with their saved threshold provenance: strict A score
`> 1.1537269353866577`, B score `> -0.2367836833000183`.
Negative scores are valid. B is null without an observed initiated relationship;
A can score a recipient. Preserve per-head reasons, `inactive/unavailable`,
`profile_support`, history/warm-up, sensor health, model version and hashes.
Unknown-device scoring is mechanically supported but unqualified for accuracy.

Monitor stream freshness as well as service readiness. The model needs no
training or online profile fitting. The service builds features and reprojects
raw causal history itself.

**Complete when:** integration accepts both flags and nulls correctly, detects
stale/unavailable evidence, excludes engineering examples from enforcement and
records the active C bundle identity. No residual-score/probability conversion
remains in dashboards or decision rules.

### Step 6. Finish the independent MUD evidence branch

**Owner: Sarveshwar Balu.**

Evaluate observed initiator/responder/protocol/service tuples against versioned
MUD permissions and the same actual inventory. Return permission result,
violation details, observation time/window, device/binding, policy version,
branch health and evidence ID. Define unavailable/unknown-policy outcomes.

Keep MUD permissions independent of C. A low anomaly score cannot authorize a
forbidden connection. A high receiving-device score does not identify that
device as the initiating attacker. Preserve direction and current binding for
response selection; authored topology edges alone do not establish permission.

**Complete when:** an allowed exchange, forbidden exchange, unknown device and
MUD branch outage produce distinct evidence tied to the same observations.

### Step 7. Implement the timed join and missing-branch behavior

**Owner: Rashwanth, with Sarveshwar.**

Join C and MUD by run/session/sensor, UTC minute, stable device and inventory
version. Retain evidence IDs, model bundle/checkpoint hashes and policy version.
Define branch deadlines, late arrivals, stale observations and unavailable
outcomes. Never substitute a neighboring window or an old device binding.

Deduplicate observation/decision IDs so replay or an HTTP timeout cannot create
duplicate actions. Reject `observation_kind=engineering` from the response
path. Record a partial/unavailable join when a branch fails.

**Complete when:** reordered arrivals and a delayed/missing branch lead to the
documented decision state, without cross-window joins or duplicate actions.

### Step 8. Run the Decision Engine in observation mode

**Owner: Rashwanth; all owners review response policy.**

Implement the agreed decision tiers using distinct C and MUD evidence semantics,
health, warm-up, support and current binding. Define scope, cooldown, escalation,
expiry and human override. Initially log proposed actions only.

Head A can describe a victim receiving attack traffic. Use the originating
flow/relationship and current network binding before selecting a target.
A logit is not a compromise probability. Keep unscored evidence unscored.
Meter/QoS rate limits and VLAN quarantine require their actual network setup.

**Complete when:** normal, permission-violating and controlled attack cases
produce explainable proposed decisions, with null/stale/partial cases handled
explicitly and no unintended switch changes.

### Step 9. Implement Ryu actions, expiry and recovery

**Owners: Anand + Rashwanth.**

Define an action request with idempotent decision ID, evidence reference,
current device binding, DPID/port, scoped match, action parameters,
priority/cookie, TTL and reason. The controller validates the binding and returns
accepted/rejected/installed status plus errors. Distinguish transport acceptance
from confirmed installation.

Test one narrow lab action first. Use OpenFlow barriers/status, table dumps,
counters and actual traffic to confirm the effect. Verify normal unaffected
traffic, expiry/removal and connectivity recovery. Make retries idempotent.
Start with temporary rules and only enable automated responses after review of
the observed behavior and the agreed team policy.

**Complete when:** a permitted test action affects only its intended target,
has a confirmed traffic effect, expires/removes correctly and cannot persist
indefinitely after integration failure.

### Step 10. Exercise failures, restarts and release rollback

**Owners: all.**

Test cold start, 15-minute neural history and one-hour rolling warm-up; healthy
silence; drops/unknown loss; clock failure; IP/MAC rebinding; missing minute;
ML/MUD/controller outage; conflicting duplicates; persistence failure; and
service restart. Verify targeted history resets and explicit unavailable states.

Follow [API replacement instructions](LIVE_GNN_API.md#5-safe-model-replacement-and-rollback)
to stage a complete supervised bundle, activate it between windows, then roll
back to the recorded ID. A same-weights export is suitable for this engineering
test. Keep all referenced directories intact. A changed frozen profile or
adapter resets model history on the next new window; unchanged profiles retain
compatible raw history. Cached retries always retain their original outputs.

**Complete when:** recovery preserves accepted results, never silently loses a
minute, and never leaves an action aimed at an obsolete binding. Capture rollback,
expiry and restart evidence in the acceptance record.

### Step 11. Connect events/dashboard and measure end-to-end delay

**Owner: Rashwanth, with Anand for switch confirmation.**

Persist input/evidence/decision/action IDs, identity/inventory versions, health,
A/B scores and flags, unscored reasons, model/policy versions and controller
outcome. Connect the dashboard to these records. Neo4j is optional; qualify any
chosen backend/frontend environment before adding startup instructions.

Timestamp packet onset, window close, evidence readiness, decision, controller
acknowledgement and confirmed traffic effect separately. Sixty-second windows
impose observation delay; HTTP inference time alone is not response latency.
Display engineering runs and stale/unavailable states clearly.

**Complete when:** one observation can be traced through both branches to an
installed/expired action and measured traffic effect, with each delay visible.

### Step 12. Sign off on the team's deployment host

**Owners: all.**

Repeat installation/fixture/regression and packet-to-API acceptance on the
actual Linux host, followed by the full joined pipeline scenarios above.
Save pinned environments, topology/inventory, MUD versions, sensor settings,
model hashes, reports, flow dumps, action/expiry traces and measured timing.

Record predictive validation separately on appropriately labeled live traffic
if claiming live accuracy. The consumed authored-household benchmarks do not
establish accuracy on other devices, homes or traffic. C has three supported
B subgroup checks that fail on the later corpus; see
[results and limitations](MODEL_RESULTS.md). Keep observation mode until the
team's integration and response gates pass.

**Complete when:** the acceptance record proves branch joins, observation
health, scoped enforcement, expiry/recovery and restart/rollback on that host.
The WSL qualification supplied here does not replace this final sign-off.

## Responsibilities after handoff

Jayan supplies separately trained/evaluated complete supervised releases.
Anand maintains the controller, testbed, observation path and binding/action
correctness. Sarveshwar maintains MUD permissions/evidence. Rashwanth maintains
the finalizer/client, joins, Decision Engine and events/dashboard. External
telemetry/evidence contracts remain stable when a compatible model is replaced;
teammates do not own feature arrays, tensor conversion or training.

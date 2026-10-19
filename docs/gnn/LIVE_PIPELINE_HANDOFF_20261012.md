# AutoMUD supervised E1+Q live pipeline handoff

Updated 19 October 2026. The repository model is **original E1+Q**, seed 42,
selected epoch 5, in `models/gnn/` (version `supervised-E1Q-20261018`). Only
the model and required loading adapter change from C; the remaining pipeline,
service configuration, frozen preprocessing and numbered owner steps stay the same.
An existing host requires a coordinated model cutover using the lifecycle API.
Saturn's installation is now qualified and its E1+Q service is running, as
recorded below. The remaining integration steps retain their team ownership.
The first controller/sensor/integration implementation on Saturn is tracked in
[Saturn live-pipeline progress](SATURN_LIVE_PIPELINE_PROGRESS_20261019.md).

The ML service, supervised feature/history adapter, frozen assets, installation
fixture and software acceptance are supplied. Teammates complete the sensor
finalizer, independent MUD branch, orchestrator, Decision Engine and Ryu action
app by following the steps below. Full datasets and training are unnecessary
for integration. Use [Linux setup](LINUX_PIPELINE_SETUP_20261012.md) for a new
host; on Saturn, start with the installed environment below.

## Saturn: prepared integration host

Saturn was prepared on 19 October 2026 with Ubuntu 24.04.4 ARM64 (`aarch64`),
4 CPUs, 23 GiB RAM, Python 3.12.3, Mininet 2.3.0, Open vSwitch 3.3.9 and
Zeek 8.0.10. All six versions in `requirements-ml-runtime.lock.txt` are installed;
Torch is the official `2.14.1+cpu` ARM64 wheel. No version substitutions were
needed. Installation left approximately 36 GB free on `/` and 47 GB on
`/mnt/data`. The data disk has a persistent mount entry; boot configuration was
checked, but the host was not rebooted during qualification.

From a workstation with an authorized Saturn SSH configuration:

```bash
ssh Saturn
source /opt/automud/activate.sh
curl --fail http://127.0.0.1:8001/readyz
curl --fail http://127.0.0.1:8001/v1/model
```

The activation script enters the project, activates `.venv-ml`, adds Zeek to
PATH, and directs temporary files and caches to the data disk. Mininet uses
`sudo /usr/bin/python3`; run ML as an ordinary user. Do not reinstall the stack
or run the unpinned `requirements.txt` in `.venv-ml`. Ryu and other integration
dependencies require separate environments qualified by their owners.

### Project, storage and service paths

| Path on Saturn | Purpose |
|---|---|
| `/opt/automud/Auto-Mud` | Shared source checkout, supplied models and fixtures |
| `/opt/automud/Auto-Mud/.venv-ml` | Qualified CPU ML environment |
| `/opt/automud/releases/supervised-E1Q-20261018` | Active root-owned, read-only model snapshot |
| `/opt/automud/releases/supervised-C-20261016` | Root-owned, read-only original C rollback snapshot |
| `/etc/automud/service.json` | Actual host-specific service configuration |
| `/etc/systemd/system/automud-gnn.service` | Installed service unit |
| `/mnt/data/automud/captures` | Packet captures, with unique output directories |
| `/mnt/data/automud/logs` | Application and Zeek logs |
| `/mnt/data/automud/tmp` | Durable service state and temporary outputs |
| `/mnt/data/automud/cache` | Package and Python caches |
| `/mnt/data/automud/qualification/20261019` | Installation acceptance reports and archived engineering state |
| `/mnt/data/automud/setup` | Installation receipt, configurations, scripts and logs |

The checkout's `tmp` symlink points to `/mnt/data/automud/tmp` and is excluded
locally from Git. Use explicit output paths on `/mnt/data/automud` for capture,
extraction and collector runs; some older tools default to the source tree.
Keep source, environments and models on `/`. Do not relocate or overwrite model
snapshots referenced by durable state.

The API runs as the dedicated `automud` account on `127.0.0.1:8001`, enabled
at boot. Its unit requires the data mount and restricts service writes to its
state/log directories. The state path is
`/mnt/data/automud/tmp/gnn-live-supervised/state.json`; the log is
`/mnt/data/automud/logs/gnn/service.log`. Logs rotate daily with seven retained
rotations and a 10 MiB threshold checked by logrotate. The team must manage
capture and Zeek-output retention separately.

```bash
sudo systemctl status automud-gnn --no-pager
tail -n 50 /mnt/data/automud/logs/gnn/service.log
```

Use `sudo systemctl stop automud-gnn` and `sudo systemctl restart automud-gnn`
when deliberately maintaining the service. Do not launch a second server with
the repository's default configuration: its port and resolved state path collide
with the installed service, and its bundle path differs from the immutable
deployment snapshot. For a development instance, choose both a separate
localhost port and a separate state file. The running service imports code from
the shared checkout; coordinate runtime edits and explicit restarts.

For workstation API access, keep this tunnel open in a separate local terminal:

```bash
ssh -N -L 8001:127.0.0.1:8001 Saturn
```

Then access `http://127.0.0.1:8001` on that workstation. No public API listener
or cloud firewall change was added. API/admin tokens are unset, so administrative
model/reset routes are disabled. Operators can follow the [API guide](LIVE_GNN_API.md)
and configure the unit's optional root-readable `/etc/automud/gnn.env` when those
routes are needed. Keep secrets out of Git.

The source installation started at `e7961cee19287acb8722eb8cb81e327d91a742bb`
on `codex/saturn-integration`; subsequent documentation commits do not change
that runtime qualification baseline. Use `git rev-parse HEAD` to identify the
current checkout. The existing `ubuntu` login belongs to `automud-dev`, which
can edit the shared checkout. Coordinate branches and changes between teammates.
No additional SSH accounts or GitHub write credentials were installed;
administrators must provision each approved teammate's access separately.

### Acceptance completed on Saturn

These are measured installation results from this ARM64 host, separate from the
earlier WSL release qualification described below:

| Check | Saturn result |
|---|---|
| E1+Q and C rollback model integrity | Six verified assets in each bundle; deployment snapshots match source bytes |
| Both installation fixtures | Each passed 9 graphs, 108 household records and 216 flags; maximum A/B score error `3.8147e-6`, below `1e-4` |
| ML/network regression | 74 passed; zero failures, errors or skips |
| Standalone Mininet connectivity | 0% loss, 2/2 replies |
| Isolated packet-to-Zeek-to-API check | Zero capture drops; all 16 controlled closed-port rows observed; exact features/edges, 12 matching flags and zero live/offline score error |
| API lifecycle | Identical retries, durable restart and temporary model stage/activate/rollback passed |
| 60-window / 12-device capacity probe | Approximately 99 ms median, 106 ms p95, 267 ms maximum; 392 MiB peak process RSS; keeps up with 60-second windows |
| Persistent systemd service | Readiness, engineering submission, identical retry and restart passed |

The authoritative installation receipt is
`/mnt/data/automud/setup/SATURN_SETUP_RECEIPT.json`, also copied to
`/opt/automud/SATURN_SETUP_RECEIPT.json`. Full Python versions are recorded in
`/mnt/data/automud/qualification/pip-freeze.txt`; system package versions are in
`/mnt/data/automud/qualification/system-package-versions.tsv`. Detailed reports
are under `/mnt/data/automud/qualification/20261019`, including `tests.xml`,
`packet-api/report.json`, `throughput/report.json` and `service-smoke/report.json`.

The engineering capture and smoke state are retained separately. The service
was left ready with fresh state, and the temporary lab bridges were cleaned up.
OVS remains running. No controller-managed deployment switch, permanent traffic
generator, Ryu app, continuous finalizer, MUD branch, Decision Engine, dashboard
or enforcement was implemented or activated. No training, dataset changes or
frozen artifact changes were made. These tests establish host compatibility;
the actual sensor and complete joined pipeline still require the steps below.
Engineering observations must be excluded from enforcement.

## What is supplied and how evidence flows

```text
Mininet -> controller-managed OVS -> dedicated mirror -> Zeek + interval finalizer
                                                               |
                                         completed UTC 60-second observations
                                                               |
                                +------------------------------+----------+
                                |                                         |
                 supplied E1+Q service                               MUD engine
                 features/history -> joint A/B                    permission evidence
                                +-------------------+---------------------+
                                                    |
                                          timed join + Decision Engine
                                                    |
                                            Ryu action endpoint
                                                    |
                                        OVS rule -> measured traffic effect
```

Only the E1+Q branch is a supervised detector. The MUD branch evaluates permissions
independently. The Decision Engine owns actions. Neo4j is optional event storage.

| ML deliverable | Supplied implementation |
|---|---|
| Frozen release | Joint `detector.pt`, clean profile, normalizer, cutoffs, feature contract, results and hash manifest |
| Stable integration | `automud.live-window.v1` input, `automud.gnn-evidence.v1` output, HTTP and standard-library client |
| Supervised adaptation | 61 raw features, exact normalization/clock, 149 current inputs, 15 strictly prior own-device vectors of width 147 |
| Live state | Ordered minutes, health/identity/gap resets, bounded history, durable save/restart, deduplication |
| Model lifecycle | Complete supervised bundle export, validation/probe, serialized activation, profile-aware history resets and targeted rollback |
| Qualification | Consumed reference reproduction, regression, independent archived feature/tensor parity, Mininet/Zeek/API acceptance and CPU capacity report |

The model uses graph-derived counts/context and **directed learned neighbor
messages**, with causal own-device history. A reports behavioral/affected-device evidence; B reports initiated
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
matching flags; 74 passing Linux tests. Reference CPU logits reproduced exactly.
An independent 80-minute comparison also matched archived batch features,
masks, edges, tensors and logits exactly, including a state save/restore.
[Deployment validation](DEPLOYMENT_VALIDATION.json) records the new release's
capture and capacity results. These checks establish software compatibility;
Saturn's native-host acceptance is recorded above; full MUD/Ryu integration
and enforcement sign-off remain team work.

The earlier WSL release's 12-device/60-window CPU capacity probe measured
approximately 91 ms median, 111 ms p95 and 227 ms maximum HTTP processing including durable
state saves, with about 753 MiB peak process RSS. Replaying the existing isolated
engineering capture observed all 16 controlled closed-port rows with recorded
zero drops and zero live/offline score error. That release check reused an existing
capture; Saturn's qualification acquired a separate isolated engineering capture.
These are engineering measurements, not attack accuracy or packet-to-enforcement
latency.

## Remaining work: follow these steps in order

Each step states the owner, actions and completion check. Keep the collected
configurations/logs/reports together as the deployment acceptance record.
Saturn's supplied ML installation is complete; start with the actual inventory
and remaining controller/sensor/integration work. Installed host tools and an
isolated acceptance pass do not complete the following deployment-specific gates.

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

Saturn already has the host networking tools from Linux setup step 2. Follow
step 9 and pin a working controller environment/image
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

Linux setup step 8's isolated packet-to-API acceptance has passed on Saturn.
Inspect the saved report, then verify the actual deployment sensor and mirror.
Repeat the isolated check after relevant capture/runtime changes or on another
host. Its bridge `amgnn0` is independent of the deployment switch; use fresh
output paths on `/mnt/data/automud`.

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

### Step 5. Use the E1+Q service and integrate the supervised evidence fields

**Owner: Rashwanth; Jayan owns model releases.**

On Saturn, reuse `automud-gnn.service` and `/etc/automud/service.json`; confirm
`/readyz` and `/v1/model` as shown above. Installation, fixtures and service
restart have passed; evidence consumption and freshness handling remain work
for this step. Do not replace the host-specific configuration with the generic
repository template or reset an integration session's accepted state.

For a new host, follow Linux setup steps 4–7. Existing New 2 installations must
first stop, back up the old bundle/state together and use the new
`tmp/gnn-live-supervised/state.json`. Do not restore old residual-model state
against overwritten files. Start the service as an ordinary user and confirm
`/readyz`, `/v1/model` and the consumed fixture.

Use returned flags with their saved threshold provenance: strict A score
`> 0.7624336779117584`, B score `> 4.921021908521652`.
Negative scores are valid. B is null without an observed initiated relationship;
A can score a recipient. Preserve per-head reasons, `inactive/unavailable`,
`profile_support`, history/warm-up, sensor health, model version and hashes.
Unknown-device scoring is mechanically supported but unqualified for accuracy.

Monitor stream freshness as well as service readiness. The model needs no
training or online profile fitting. The service builds features and reprojects
raw causal history itself.

**Complete when:** integration accepts both flags and nulls correctly, detects
stale/unavailable evidence, excludes engineering examples from enforcement and
records the active E1+Q bundle identity. No residual-score/probability conversion
remains in dashboards or decision rules.

### Step 6. Finish the independent MUD evidence branch

**Owner: Sarveshwar Balu.**

Evaluate observed initiator/responder/protocol/service tuples against versioned
MUD permissions and the same actual inventory. Return permission result,
violation details, observation time/window, device/binding, policy version,
branch health and evidence ID. Define unavailable/unknown-policy outcomes.

Keep MUD permissions independent of E1+Q. A low anomaly score cannot authorize a
forbidden connection. A high receiving-device score does not identify that
device as the initiating attacker. Preserve direction and current binding for
response selection; authored topology edges alone do not establish permission.

**Complete when:** an allowed exchange, forbidden exchange, unknown device and
MUD branch outage produce distinct evidence tied to the same observations.

### Step 7. Implement the timed join and missing-branch behavior

**Owner: Rashwanth, with Sarveshwar.**

Join E1+Q and MUD by run/session/sensor, UTC minute, stable device and inventory
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

Implement the agreed decision tiers using distinct E1+Q and MUD evidence semantics,
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

Use Saturn's recorded installation acceptance as the host baseline. Repeat
installation/fixture/regression and packet-to-API checks after relevant changes
or on a different host, then run the full joined pipeline scenarios above.
Save pinned environments, topology/inventory, MUD versions, sensor settings,
model hashes, reports, flow dumps, action/expiry traces and measured timing.

Record predictive validation separately on appropriately labeled live traffic
if claiming live accuracy. The consumed authored-household benchmarks do not
establish accuracy on other devices, homes or traffic. E1+Q's aggregate gain
over retained C includes an A recall tradeoff; see
[results and limitations](MODEL_RESULTS.md). Keep observation mode until the
team's integration and response gates pass.

**Complete when:** the acceptance record proves branch joins, observation
health, scoped enforcement, expiry/recovery and restart/rollback on that host.
Neither the earlier WSL qualification nor Saturn's isolated installation checks
replace this final joined-pipeline sign-off.

## Responsibilities after handoff

Jayan supplies separately trained/evaluated complete supervised releases.
Anand maintains the controller, testbed, observation path and binding/action
correctness. Sarveshwar maintains MUD permissions/evidence. Rashwanth maintains
the finalizer/client, joins, Decision Engine and events/dashboard. External
telemetry/evidence contracts remain stable when a compatible model is replaced;
teammates do not own feature arrays, tensor conversion or training.

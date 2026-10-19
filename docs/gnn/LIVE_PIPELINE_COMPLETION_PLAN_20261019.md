# AutoMUD live pipeline completion plan

Updated 19 October 2026. This plan converts the remaining acceptance gates in
`LIVE_PIPELINE_HANDOFF_20261012.md` into an implementation sequence for the
`codex/live-pipeline` baseline. It is an execution plan, not a claim that the
deployment is complete.

## 1. Objective and current baseline

The objective is to turn the validated Saturn engineering pipeline into a
durable, observable and reviewable live pipeline while preserving the supplied
E1+Q model contract. The finished system must trace one completed sensor window
through independent GNN and MUD evidence, a deadline-driven join, an explainable
decision and, only after explicit approval, a scoped OpenFlow action with expiry
and recovery.

The starting branch is `codex/live-pipeline` at commit `094020f`. It currently
provides:

- a 12-device engineering configuration and lab MUD policy;
- an OS-Ken OpenFlow 1.3 controller with idempotent scoped block rules;
- a controller-managed Mininet topology and dedicated Zeek mirror;
- UTC-minute Zeek telemetry and health records;
- a durable per-window pending/accepted queue;
- synchronous E1+Q and MUD evaluation, strict identity joining and observation
  decisions;
- append-only JSONL events; and
- a successful lab action/TTL/recovery test and 78 passing tests.

This baseline is intentionally configured with `observation_kind=engineering`
and `decision.mode=observe`. Those gates remain unchanged until every release
gate in section 17 is satisfied.

## 2. Non-negotiable safety and correctness rules

1. Do not edit, retrain or replace the frozen E1+Q bundle as part of pipeline
   integration. Use the model lifecycle API for a separately approved release.
2. Treat Head A and Head B values as raw logits and flags with saved threshold
   provenance. Never label them as probabilities or compromise confidence.
3. Keep MUD authorization independent from anomaly evidence. Neither branch may
   silently replace or infer the other.
4. Never fabricate an inventory lease, device identity, DNS name, branch result,
   sensor-health value or successful action status.
5. Never convert absent or unhealthy telemetry into benign zeros. Preserve
   null, unavailable, stale and partial states through the dashboard.
6. Reject cross-window, cross-session, cross-sensor, cross-inventory and stale
   binding joins.
7. Persist a window before sending it. Retries must reuse identical bytes and
   accepted windows must retain their original results.
8. Automatic actions require both `observation_kind=live` and
   `decision.mode=enforce`, a complete healthy join, current binding validation
   and an approved response policy.
9. All enforcement rules require a bounded TTL, namespaced cookie, confirmed
   OpenFlow barrier and recorded expiry/removal. No integration failure may
   leave an indefinite rule.
10. Do not commit credentials, API tokens, SSH keys, private host information,
    runtime state or captured user traffic.

## 3. Human inputs required before live enablement

Implementation can proceed using engineering fixtures, but the following values
must come from the team before live sign-off. Missing values block enablement;
they do not block validators, simulations or failure tests.

| Input | Required owner/reviewer | Required content |
|---|---|---|
| Approved inventory | Anand and Rashwanth; Sarveshwar reviews MUD identity mapping | Stable device ID/type, MAC, IP lease intervals in UTC, switch port or binding source, unknown-device convention and inventory version |
| Controller runtime decision | Anand | Approve OS-Ken 2.8.1 as the maintained Ryu-compatible runtime, or provide a pinned Ryu environment/image |
| Sensor placement | Anand | Deployment bridge/DPID, mirror interface, sensor ID, clock source, drop counter source and maintenance procedure |
| MUD policy | Sarveshwar plus team review | Per-device source policy, local permissions, external CIDRs/FQDNs, protocols/ports, DNS evidence rules, default outcome and policy version |
| Response policy | All owners | Decision tiers, eligible signals, scope, cooldown, escalation, maximum TTL, override roles and rollback authority |
| Dashboard deployment | Rashwanth | Bind address, authentication boundary, retention period and whether JSONL or SQLite is the operational store |
| Sign-off window | All owners | Scheduled test period, traffic fixtures, outage authority and people accepting each gate |

Store approved non-secret configuration in versioned repository files. Store
secrets in service environment files with restrictive permissions, outside Git.

## 4. Delivery sequence and dependencies

Execute the phases in this order. A phase may be developed with fixtures before
its manual inputs arrive, but it may not be marked accepted until its exit gate
passes on the chosen deployment host.

| Phase | Handoff step | Depends on | Main deliverable |
|---|---:|---|---|
| 0 | All | Current branch | Reproducible baseline and acceptance workspace |
| 1 | 1 | Approved schema | Time-bounded inventory and binding validation |
| 2 | 2 | Runtime decision | Pinned controller qualification receipt |
| 3 | 3 | Phases 1-2 | Repeatable sensor/mirror qualification |
| 4 | 4 | Phase 3 | Managed finalizer with durable cursor and metrics |
| 5 | 5 | Phase 4 | Freshness-aware E1+Q evidence adapter |
| 6 | 6 | Phases 1, 3 | Complete independent MUD matcher and name context |
| 7 | 7 | Phases 4-6 | Durable deadline-driven asynchronous join |
| 8 | 8 | Phase 7 | Versioned decision policy, cooldown and override |
| 9 | 9 | Phases 1, 2, 8 | Hardened action lifecycle and recovery |
| 10 | 10 | Phases 3-9 | Automated failure and rollback matrix |
| 11 | 11 | Phases 7-10 | Trace dashboard and stage latency |
| 12 | 12 | All prior phases | Signed host acceptance record |

## 5. Phase 0: freeze and reproduce the baseline

### Implementation

1. Create a new implementation branch from `codex/live-pipeline`; do not work
   directly on `main`.
2. Record the Git commit, OS/kernel, Python, OS-Ken/Ryu, OVS, Mininet, Zeek and
   systemd versions in a new run directory under the established qualification
   root.
3. Record `/readyz`, `/v1/model`, active model ID/hashes and the current service
   unit hashes without copying tokens.
4. Save sanitized copies of deployment configuration, policy versions, service
   status, controller listeners, switch tables and disk capacity.
5. Run the existing model checks and test suite. Repeat the controller topology,
   completed-window and scoped-action smoke tests in engineering mode.
6. Write a machine-readable baseline manifest containing artifact paths and
   SHA-256 hashes.

### Acceptance evidence

- Existing tests pass with no new failures.
- The model identity matches `supervised-E1Q-20261018`.
- Engineering action dispatch remains disabled outside the explicit smoke test.
- A baseline receipt links every command output and artifact hash.

### Rollback point

Stop services started for the test, remove only the test-owned Mininet bridge
and restore the previously active repository commit. Do not delete ML state.

## 6. Phase 1: approved inventory and time-bounded bindings

### Code changes

- Add a live deployment configuration separate from `configs/live/saturn.json`;
  preserve the existing file as the reproducible engineering fixture.
- Extend `integration/live/config.py` to represent binding intervals rather than
  assuming one permanent IP/MAC/port tuple per device.
- Validate UTC start/end ordering, non-overlapping bindings, uniqueness within
  each interval, subnet membership, DPID/port validity and inventory version.
- Resolve inventory for the exact `[window_start, window_end)` interval. Refuse
  ambiguous intervals and record unknown devices honestly.
- Compare configured bindings with the controller's observed MAC/port table
  before any action becomes eligible.

### Recommended contract

Use a versioned `automud.deployment.v2` schema for live bindings while retaining
read compatibility for the v1 lab fixture. Each binding should include
`device_id`, `device_type`, `mac`, `ip`, `switch_port`, `valid_from` and optional
`valid_until`. Record the lease/binding source and inventory hash in each window.

### Tests

- overlapping leases and duplicate IP/MAC/port assignments are rejected;
- a rebinding exactly at a minute boundary selects the correct interval;
- a binding change within one window produces an unavailable/ambiguous result;
- unknown devices retain an unknown stable identity;
- configured and controller-observed bindings agree before an action request;
- stale inventory versions cannot join with current evidence.

### Exit gate

For every test minute, each address resolves to at most one intended device and
both evidence branches plus the controller report the same inventory version and
current binding.

## 7. Phase 2: controller runtime qualification

### Implementation

1. Record the team's OS-Ken-versus-Ryu decision. If OS-Ken is accepted, pin the
   Ubuntu package version and document `osken-manager` as the launcher. If Ryu is
   required, isolate and pin it in a separate environment or image.
2. Add a controller qualification command/script that checks imports, manager
   help, OpenFlow 1.3 listener, REST listener, DPID connection and fail mode.
3. Save controller startup arguments, service-unit hash, OVS controller state,
   protocol list, table dump and current binding map.
4. Verify secure fail mode behavior deliberately during controller loss. Record
   the expected traffic effect; do not let a default silently decide it.

### Tests and exit gate

- the intended DPID connects to exactly the intended controller;
- baseline traffic succeeds and appears in the actual switch tables;
- restart and disconnect clear or reconstruct binding state safely;
- runtime versions and commands are present in the receipt.

## 8. Phase 3: sensor and mirror qualification

### Code changes

- Make mirror creation a reconciliation operation: locate the named mirror,
  verify its selected ports and output port, and avoid duplicate mirror objects.
- Record offload settings and failures for every relevant interface.
- Add a qualification traffic generator covering both directions, established
  and rejected TCP connections, UDP, long-lived flows across a minute boundary,
  a healthy silent minute and a controlled sensor interruption.
- Record kernel/OVS/Zeek counters and a method for distinguishing loss from an
  unavailable loss measurement.
- Extend the Zeek policy only when needed to carry trustworthy DNS/name evidence;
  keep IP telemetry and health records versioned.

### Tests

- each controlled packet appears once, with correct direction and byte/packet
  allocation;
- continued connections span windows without becoming invented new flows;
- rejected/timeout attempts are represented causally;
- a healthy silent minute has empty telemetry and healthy capture progress;
- interruption, clock failure and unknown drops become unhealthy evidence;
- startup and shutdown partial windows are never marked complete.

### Exit gate

A saved report proves both directions, zero measured drops in the healthy run,
no duplicate copies, correct causal fields and honest degraded-state behavior.

## 9. Phase 4: continuous finalizer service

The existing daemon chooses a candidate minute from wall-clock time and keeps a
completed set only in memory. Replace that behavior with watermark-driven,
durable progression.

### Code changes

1. Add a durable cursor/ledger containing the last accepted minute, pending
   minutes, attempts, next retry, last error and payload hash.
2. Discover finalizable windows from sensor health watermarks. Finalize a minute
   only when the watermark reaches its end, or when a documented branch deadline
   requires an explicit incomplete record.
3. Use an exclusive process lock. A second finalizer must exit without touching
   the queue.
4. Persist the canonical payload atomically before the first submission. Verify
   its hash before every retry.
5. Implement bounded exponential retry with jitter while retaining the exact
   payload. Resume pending work in chronological order after restart.
6. Persist startup/shutdown partial-window disposition explicitly.
7. Expose queue depth, oldest age, last watermark, last accepted window, retry
   count and last error through a status CLI and machine-readable status file.
8. Add `configs/live/automud-finalizer.service` with explicit user, working
   directory, environment file, restart policy and writable paths.

### Tests

- traffic, silence and interruption across several ordered minutes;
- crash after payload persistence but before submission;
- timeout after server acceptance followed by identical retry;
- restart with pending backlog and no duplicate accepted result;
- corrupt payload/hash, unwritable queue and unavailable disk;
- two attempted daemon instances;
- delayed health watermark and shutdown during a partial minute.

### Exit gate

The finalizer runs under systemd, survives restart, never silently skips a
minute and exposes enough state to diagnose backlog without opening payloads.

## 10. Phase 5: freshness-aware E1+Q integration

### Code changes

- Check `/readyz` and `/v1/model` at startup and periodically; record active
  bundle ID, checkpoint hashes and contract version.
- Validate every `automud.gnn-evidence.v1` response before joining it. Preserve
  both heads, nulls, flags, reasons, support, warm-up/history and health fields.
- Derive freshness from the evidence/window identity and receipt timestamps;
  reject stale evidence instead of reusing it.
- Separate service readiness, stream freshness and model availability in events
  and dashboard fields.
- Ensure engineering observations can be processed for evidence but can never
  enter the response path.

### Tests and exit gate

- Head A/Head B flags and nulls are retained exactly;
- negative logits remain valid and no probability conversion exists;
- stale, unavailable, unsupported and warming states remain distinct;
- a service restart and identical retry preserve the accepted result;
- every accepted record includes the active E1+Q identity and hashes.

## 11. Phase 6: complete independent MUD evidence

### Code changes

1. Replace the lab-only tuple list with a compiled, versioned policy supporting
   local device identities, CIDRs and reviewed FQDN/service rules.
2. Add a normalized DNS/name-evidence record with observation time, answer TTL,
   sensor identity and expiry. Never apply an expired or future DNS answer.
3. Match direction, initiator, responder, protocol and service port explicitly.
4. Emit distinct `allowed`, `denied`, `unknown_device`, `unknown_policy` and
   `unavailable` results with matched rule/source and policy hash.
5. Validate policy completeness at startup without treating an unknown policy as
   permission. Reload policies only between windows and record the new version.

### Tests

- allowed local exchange and forbidden local exchange;
- approved external FQDN resolved inside TTL;
- missing, expired and conflicting DNS context;
- unknown initiator and known device with no external policy;
- MUD parser/policy outage and policy replacement between windows;
- same observation retried with the same policy returns the same evidence ID.

### Exit gate

The five outcomes remain distinguishable and traceable to one observation,
binding and immutable policy version without using GNN scores as permission.

## 12. Phase 7: durable asynchronous join

The existing orchestrator evaluates both branches sequentially in one call.
Replace that assumption with a durable join coordinator.

### Recommended design

Use Python's built-in SQLite in WAL mode with full synchronization. Key an
observation by `(run_id, session_id, sensor_id, inventory_version,
window_start, window_end, observation_kind)`. Store observations, branch
evidence, deadlines, joins, decisions and action-dispatch state with uniqueness
constraints. Keep large canonical payloads in the existing hashed spool and
store paths/hashes in SQLite.

### Code changes

- accept GNN and MUD arrivals independently;
- validate every branch against the complete observation key;
- close the join when both branches arrive or the configured deadline expires;
- record partial/unavailable joins on deadline, never substitute another minute;
- define late evidence behavior: retain it for audit but do not mutate a closed
  decision unless an explicit re-evaluation policy is approved;
- make observation, join and decision IDs deterministic;
- reserve a decision/action dispatch row transactionally before calling the
  controller so replay cannot create duplicate actions;
- add retention and integrity-check commands.

### Tests and exit gate

Test both arrival orders, delayed branch, missing branch, duplicate identical
evidence, conflicting duplicate, stale branch, wrong inventory/session, process
restart before deadline and restart during dispatch. Each case must end in the
documented state with no cross-window join or duplicate action.

## 13. Phase 8: decision policy, cooldown and human override

### Code changes

- Move response tiers and timing into a versioned decision-policy file.
- Keep Head A victim/behavioral meaning separate from Head B initiated-link
  meaning. Require attributable initiating flow and current binding before a
  block target is selected.
- Persist cooldown by target, scope and action type. Define whether repeated
  windows extend, suppress or escalate an existing proposal.
- Implement escalation using explicit evidence counts/time bounds rather than
  invented probabilities.
- Add a durable human override with actor, reason, creation time, expiry and
  scope. Expired overrides must fail closed and remain auditable.
- Record every withholding reason, including partial branch, unhealthy sensor,
  warm-up, unsupported profile, stale evidence, engineering observation,
  cooldown, override and binding mismatch.

### Tests and exit gate

Normal, allowed, forbidden, controlled attack, victim-only A flag, B flag,
null, partial, stale and unhealthy cases must produce deterministic explainable
proposals. Cooldown, escalation and override expiry must survive restart. No
observation-mode case may alter the switch.

## 14. Phase 9: action lifecycle hardening

### Code changes

1. Revalidate inventory version, DPID, MAC, IP and current learned port at the
   controller immediately before installation.
2. Enforce action allowlists, priority range, maximum TTL, cookie namespace and
   match-scope validation. Reject an empty or broader-than-policy scope.
3. Preserve accepted, rejected, installing, installed, expired, removed and
   failed states separately. Transport success is not installation success.
4. Use barriers and table/counter checks for installation. Add an explicit
   idempotent revoke endpoint and safe startup reconciliation for owned cookies.
5. On controller restart, recover status from actual switch rules and expire
   orphaned rules according to their original deadline.

### Tests and exit gate

Repeat the existing target/unaffected/recovery test, then add stale binding,
wrong DPID/port, overlong TTL, conflicting retry, disconnect during install,
controller restart and revoke tests. An accepted lab action must affect only its
target, be confirmed by traffic and counters, and disappear by its deadline.

## 15. Phase 10: failure, restart and model rollback matrix

Create an automated scenario runner that records preconditions, injection,
expected state, actual state, artifact paths and pass/fail. Required scenarios:

| Scenario | Required result |
|---|---|
| Cold start and first 15 minutes | Explicit history/warm-up state; no unsafe action |
| One-hour rolling warm-up | State progression visible and bounded |
| Healthy silent minute | Empty telemetry with healthy evidence |
| Drops or unknown loss | Unhealthy/unavailable, never benign |
| Clock unsynchronized | Window withheld from enforcement |
| IP/MAC rebinding | Old binding rejected; targeted history reset as specified |
| Missing minute | Gap recorded and correct model reset behavior |
| GNN outage | Timed partial join and withheld action |
| MUD outage | Timed partial join and withheld action |
| Controller outage | Decision retained; no false installed status |
| Conflicting duplicate | Quarantined/error state, no second decision |
| Persistence failure | Processing stops visibly before losing accepted state |
| Service restart | Backlog resumes in order without duplicate action |
| Same-weights model activation/rollback | Serialized between windows; identity and history behavior recorded |
| Expiry during integration outage | Rule still expires and traffic recovers |

Run disruptive cases only in the isolated lab or an approved maintenance
window. The phase passes only when accepted results survive recovery, no minute
is silently lost and no rule targets an obsolete binding.

## 16. Phase 11: events, dashboard and end-to-end latency

### Event contract

Add timestamps for packet/flow onset, window close, sensor watermark, payload
persisted, GNN ready, MUD ready, join closed, decision produced, controller
accepted, barrier confirmed, traffic effect confirmed and action expired. Keep
wall-clock synchronization state with each timing record.

### Dashboard implementation

- Build a read-only backend over the durable event/join store.
- Add views for service and stream health, queue backlog, windows, both evidence
  branches, join status, decisions, controller lifecycle and failures.
- Display raw A/B logits, flags, thresholds and unscored reasons accurately.
- Mark engineering, partial, stale, unknown and unhealthy records prominently.
- Trace all IDs and versions from one observation to policy/model/controller
  outcome.
- Show stage durations separately. Do not present HTTP inference time as total
  response latency; the 60-second window delay must remain visible.

### Exit gate

One controlled observation is traceable through both branches to an installed
and expired lab action, with packet-to-effect and every intermediate delay shown.

## 17. Phase 12: final host acceptance and enablement decision

1. Repeat installation, model, fixture and regression checks after all changes.
2. Run the full traffic/silence/interruption, async-join, decision, action,
   expiry, restart, outage and rollback scenarios.
3. Save pinned versions, unit files, sanitized configuration, inventory and
   policy hashes, sensor settings, model hashes, reports, flow dumps, counters,
   action traces and latency measurements.
4. Produce a final JSON receipt plus a human-readable report linking every
   handoff completion check to evidence.
5. Obtain named owner review for inventory, controller/sensor, MUD, decision
   policy and operations.
6. If any gate fails, retain engineering/observe mode and record the blocker.
7. Only after all reviews pass, schedule a separate controlled change to set
   `observation_kind=live` and, later, `decision.mode=enforce`. Make each change
   independently reversible and repeat the scoped canary action.

Live predictive accuracy is a separate claim. Do not infer it from engineering
fixtures or host qualification; it requires appropriately labeled live traffic
and a separate validation report.

## 18. Required artifacts and naming

For each acceptance run, create one immutable run directory containing:

- `manifest.json`: commit, versions, command hashes and artifact hashes;
- `runtime.json`: run/session/sensor/inventory identity and paths;
- `service-status/`: readiness and systemd state;
- `sensor/`: Zeek/OVS counters, offload state and health logs;
- `windows/`: canonical persisted payload hashes and acknowledgements;
- `evidence/`: GNN and MUD evidence IDs and versions;
- `joins/`, `decisions/` and `actions/`: lifecycle records;
- `flows/`: before/during/after table dumps and counters;
- `latency.json`: all stage timestamps and derived durations;
- `failure-matrix.json`: scenario results; and
- `report.md`: concise human-readable findings and unresolved blockers.

Runtime evidence belongs under the configured data disk, not in Git. Commit only
sanitized fixtures, schemas, scripts and redacted example reports.

## 19. Commit and review strategy

Use one reviewable commit per phase or coherent sub-phase. Each commit message
must state the behavior added, not merely the file changed. Before pushing:

1. run targeted tests for the modified behavior;
2. run the existing ML/network/integration regression suite;
3. inspect the diff for secrets and runtime artifacts;
4. update the progress receipt with tests and remaining gates; and
5. verify that the committed configuration still defaults to engineering and
   observe mode.

Do not merge an enablement change with implementation code. Inventory approval,
policy approval and enforcement enablement must remain separately reviewable.

## 20. Final definition of done

The handoff is complete only when the acceptance record proves all of the
following on the selected host:

- exact inventory and binding agreement across sensor, branches and controller;
- trustworthy complete, silent, partial and interrupted windows;
- durable ordered finalization and exact retries;
- correct E1+Q null/freshness/version semantics;
- independent versioned MUD outcomes including external context;
- deadline-driven joins with late, missing and duplicate handling;
- explainable decisions with durable cooldown and overrides;
- scoped idempotent actions with confirmed effect, expiry and recovery;
- safe behavior across the complete failure/restart/rollback matrix;
- traceable events and honest end-to-end latency; and
- named team approval for the host and response policy.

Until then, the correct operational state is observation mode.

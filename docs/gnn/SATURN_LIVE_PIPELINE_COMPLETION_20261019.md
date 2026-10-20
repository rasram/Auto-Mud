# Saturn live-pipeline completion record

Recorded 19 October 2026 for branch `codex/live-pipeline-completion`. This
record describes the engineering implementation and measured Saturn evidence.
It does not approve production inventory, policy or automatic enforcement.

## Engineering observation update — 20 October 2026

See the [dashboard continuation record](../dashboard/SATURN_DASHBOARD_CONTINUATION_20261020.md)
for the new supervised runtime, three consecutive complete scoreable windows,
15-prior-window history receipt, clean stop/restart, dashboard corrections and
final 103-test Python / 5-test frontend validation. All twelve devices receive
both logits; full warm-up still requires one uninterrupted hour. Jayan approved
boot auto-start for the isolated engineering testbed and kept suppression
controls locked. The existing model, dataset, policy, inventory and engineering /
observe gates remain unchanged. Archived controller tests are visible with honest
provenance, but a new packet/window-linked enforcement lifecycle and the host
persistence-fault scenario remain pending separate approval/evidence.

## Implemented

- Deployment schema v2 supports time-bounded IP/MAC/switch-port bindings while
  retaining the v1 engineering fixture. Ambiguous and conflicting intervals are
  rejected before processing.
- The continuous finalizer follows topology run changes, records stop
  boundaries, isolates queues per run, locks out a second daemon, persists exact
  payloads, retries with backoff and exposes queue/coordinator status.
- The E1+Q adapter validates service/model identity, response schema, complete
  observation identity and evidence freshness.
- Independent MUD evaluation supports local rules, external CIDRs and FQDNs
  backed by sensor DNS answers with TTL and sensor identity.
- SQLite provides durable asynchronous joins, late-branch audit, deterministic
  decisions and transactional action reservations.
- The decision engine loads a versioned policy and persists cooldown,
  consecutive-window state and expiring suppress-only human overrides.
- The controller validates current DPID/MAC/IP/port bindings, narrow TCP/UDP
  scope, priority and TTL; confirms installs with barriers; supports idempotent
  revoke; clears owned rules on reconnect; and preserves terminal lifecycle
  state across asynchronous flow-removal events.
- An operations dashboard on loopback port 8090 exposes service health, an
  interactive MUD relationship map, device Head A/B raw-logit evidence,
  explainable alerts, controller action lifecycle, guarded suppressions and
  complete trace-stage timing. Administrative controls default to locked.
- The acceptance collector writes a hashed manifest, JSON failure matrix and
  Markdown report without turning missing owner approvals into passes.

The installed services are `automud-gnn`, `automud-controller`,
`automud-finalizer` and `automud-dashboard`. All are enabled and active. The
committed controller rejects engineering actions unless an explicit temporary
systemd override is installed for an isolated test. The override used below was
removed, and the controller was restored with
`AUTOMUD_CONTROLLER_ALLOW_ENGINEERING_ACTIONS=false`.

## Validation evidence

The full ML, network and integration suite passed **87 tests** with no failures,
errors or skips. PyTorch emitted one `torch.jit.script` future-deprecation
warning. The JUnit evidence is:

`/mnt/data/automud/live/acceptance/saturn-20261019T144715Z/tests.xml`

The multi-minute run `saturn-20261019T144715Z` produced one honest startup
partial window and one complete healthy window. The complete window had zero
measured capture drops, synchronized time, available GNN and MUD branches, a
closed decision and no action because the observation was engineering data.

The controlled fault run `saturn-20261019T145521Z` forced
`clock_synchronized=false` and stopped Zeek during the second window. Both
accepted records remained incomplete/unhealthy, were withheld by the Decision
Engine and dispatched zero actions.

The scoped action run `saturn-20261019T150036Z` used a temporary engineering
approval and proved:

- identical requests reused the same action and cookie;
- the TCP rule blocked only the intended source/destination/service tuple;
- unaffected traffic stayed reachable;
- hard expiry restored target traffic;
- explicit revoke ended in stable `removed` state and restored traffic; and
- an installed rule remained effective during controller outage, expired in
  OVS, restored traffic while the controller was still down, and left no stale
  controller action after restart.

The final acceptance receipt is:

`/mnt/data/automud/live/acceptance/saturn-20261019T144715Z/failure-matrix.json`

Receipt ID:
`a6e716af43e50f83aba018988a29c5fa8006ee3d93c24a779126b9977ed4de5c`.
Nine automated scenarios passed. The one remaining host-fault scenario is a
controlled persistence/disk failure with backlog recovery; deterministic tests
already cover exact pending bytes across process restart, but the host-level
fault has not been injected.

### Dashboard verification update — 20 October 2026

After the dashboard expansion, the current regression suite passed **92 tests**
with the same existing PyTorch future-deprecation warning. Both dashboard and
finalizer services were active and enabled. All eight dashboard read endpoints
returned HTTP 200; security headers were present; and an unauthenticated
override request returned HTTP 401 without changing the protected ledger.

All six views passed desktop and 390 x 844 responsive checks with no browser
warnings/errors or horizontal overflow. The deployed snapshot showed 12
devices, 4 operational alerts, 6 trace summaries and 120 recent relationship
edges. The configuration remained `engineering / observe`, and administrative
controls remained locked because no dashboard admin token was configured.

This verifies the Step 11 dashboard software and observation-mode deployment.
Production sign-off still requires the access/retention decision and the other
owner approvals below; it also requires retaining an installed/expired action
and measured traffic-effect trace in the final acceptance dataset.

## Remaining gates

The software is complete enough for engineering observation. The handoff is
not eligible for a production/live sign-off until the team supplies and reviews:

1. the actual live inventory, binding/lease source and inventory version;
2. production MUD rules, external services and DNS evidence policy;
3. response tiers, cooldown/escalation, override roles, TTL and rollback
   authority;
4. the dashboard access boundary and retention policy;
5. a controlled persistence/disk-failure acceptance window; and
6. named owner acceptance for inventory, controller/sensor, MUD, response and
   operations.

Keep `observation_kind=engineering` and `decision.mode=observe` until those
items are complete. Enabling live observations and enabling enforcement are two
separate reviewed changes.

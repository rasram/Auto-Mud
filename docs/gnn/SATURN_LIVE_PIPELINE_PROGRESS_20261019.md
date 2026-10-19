# Saturn live-pipeline implementation progress

Recorded 19 October 2026. This receipt covers the first implementation against
the ordered live handoff. It supplements the installation receipt; it does not
declare the team deployment complete or enable automatic enforcement.

The ordered implementation and acceptance work for the remaining gates is in
[the live-pipeline completion plan](LIVE_PIPELINE_COMPLETION_PLAN_20261019.md).
The subsequent completion-branch implementation and measured acceptance runs
are recorded in
[the Saturn live-pipeline completion record](SATURN_LIVE_PIPELINE_COMPLETION_20261019.md).

This file remains the receipt for the earlier `codex/live-pipeline` baseline.
The completion record supersedes its test counts and remaining-code list; the
manual production gates stated below still apply.

## Implemented on the `codex/live-pipeline` branch

- `configs/live/saturn.json` defines the 12-device supervised engineering
  inventory, deterministic IP/MAC/switch-port bindings, DPID, controller,
  sensor, storage, E1+Q route and decision safety gates.
- Ubuntu's packaged OS-Ken 2.8.1 is installed as the maintained Ryu-compatible
  OpenFlow runtime. `automud-controller.service` is enabled and binds OpenFlow
  port 6653 and its action API to loopback only.
- `network/sdn/automud_controller.py` supplies OpenFlow 1.3 secure-mode baseline
  forwarding, current MAC/port learning, stale-binding cleanup, exact scoped
  block rules, barriers, idempotent decision IDs, cookies, hard TTLs and action
  status.
- `network/testbed/live_topology.py` creates the controller-managed switch,
  fixed inventory, dedicated mirror output and Zeek sensor namespace. It writes
  the actual lease start, DPID, interface and log paths to each run receipt.
- `network/zeek/automud-window.zeek` now emits one health record for every UTC
  minute, including healthy silent minutes, Zeek's native capture-drop delta,
  watermark, clock state and honest partial-window status.
- `integration/live/finalizer.py` persists an exact outgoing envelope before
  submission, keeps failed payloads pending, reuses acknowledged results, and
  sends incomplete/unhealthy windows honestly.
- `integration/live/mud.py` evaluates local tuples against a distinct versioned
  policy, retains policy sources and emits allowed, denied, unknown-device,
  unknown-policy and unavailable outcomes. External DNS/network permissions
  remain unknown because the current telemetry contract has no resolved-domain
  evidence.
- The orchestrator preserves both evidence branches, performs an exact
  session/sensor/inventory/minute join, records append-only events and produces
  explainable observation-mode decisions. Engineering observations and partial
  or unhealthy joins cannot dispatch actions.

## Saturn qualification evidence

| Check | Result |
|---|---|
| Existing plus new tests | 78 passed |
| Controller runtime | OS-Ken 2.8.1, systemd active/enabled, loopback listeners |
| OpenFlow testbed | Intended DPID connected; all 12 MAC/port bindings learned |
| Baseline traffic | 132/132 device-to-device ping replies, 0% loss |
| Mirrored Zeek capture | 1,092 packets in the complete-window run, 0 dropped, 0 unprocessed |
| Completed-window pipeline | 14 rows, healthy E1+Q and MUD branches, complete join, observation decision, zero dispatched actions |
| Scoped action | Target loss 0% before, 100% during; unaffected traffic 0% loss; target recovered to 0% loss after TTL |
| Idempotency/installation | Identical request reused its cookie; OpenFlow barrier confirmed installation |
| Cleanup | Action expired; `s1` removed; controller cleared disconnected switch bindings |

Run artifacts are under `/mnt/data/automud/live/runs`. The completed-window
smoke result is `/mnt/data/automud/live/finalizer-smoke.json`; the action run's
`controller-action-smoke.json` contains the request, status transitions, flow
dump and traffic measurements. Durable joined events are in
`/mnt/data/automud/live/events.jsonl`.

## Safety state and remaining gates

The committed configuration has `observation_kind=engineering` and
`decision.mode=observe`. The E1+Q API and action API remain loopback-only. No
automatic action path is enabled.

The following work still blocks final sign-off:

1. Team review and replacement of the engineering inventory/policy with the
   approved live inventory, lease source and complete MUD name/network context.
2. Long-running finalizer service management, queue/backlog monitoring and the
   traffic/silence/sensor-interruption acceptance sequence.
3. A deadline-driven asynchronous join test for reordered, late and missing
   branches. The current orchestrator rejects mismatched evidence and records
   unavailable branches, but processes the two local branches in one call.
4. Cooldown/escalation and human-override policy review before changing the
   observation gate.
5. Cold start, warm-up, rebinding, clock, persistence, outage, restart and model
   rollback scenarios from handoff step 10.
6. Dashboard/event views, end-to-end timing stages and the complete team
   acceptance record from steps 11–12.

Keep automatic enforcement disabled until these gates and the ownership reviews
in the handoff are complete.

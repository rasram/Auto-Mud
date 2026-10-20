# Saturn dashboard continuation — 20 October 2026

Continues `0457a1f` on `codex/live-pipeline-completion`. The dashboard now has
fresh engineering observations. This is not production or accuracy sign-off.

## Runtime and scored observations

`automud-testbed.service` supervises the controller-connected Mininet topology,
the mirrored Zeek sensor and low-rate local TCP probes. Jayan explicitly approved
enabling this engineering testbed at boot on 20 October. The service runs as root
because Mininet requires network namespaces and OVS privileges. Existing ML,
controller, finalizer and dashboard services retain their roles.

- `s1` connects to loopback port 6653, with all twelve configured MAC/port bindings.
- The sensor receives mirrored traffic on `sensor-eth0`; baseline connectivity
  passed 132/132 replies.
- Controlled probes exercise the six existing local MUD permission rules and a
  deliberate port-18080 denied ring. These are engineering probes, not realistic
  household normal traffic, labelled training samples or accuracy evidence.
- Run `saturn-20261020T112127Z` retained 16 complete joined windows when the
  history receipt was saved. Three consecutive windows passed identity, health,
  zero-drop, frozen cutoff/flag, twelve-device A/B-score and no-action checks.
- All devices had 15 prior windows in the newest sampled window. **Full warm-up
  also requires 3600 observed seconds**, per `ml/live/graphs.py`; that gate was
  not completed by this receipt. Scores retain their actual warm-up metadata.
- Clean service shutdown recorded `active=false` and `stopped_at`, removed `s1`,
  disconnected the switch, and showed **Runtime stopped** in the browser.
  Observation restarted successfully and complete scoreable windows returned.

Model weights, cutoffs, feature contracts, normalization, profiles, inventory,
policy and dataset assignments were not changed. Live deployment remains
`engineering / observe`; the controller's engineering-action gate remains off.

## Dashboard changes

- Separate dashboard refresh time, observation time/age, runtime start/stop,
  switch connectivity and sensor input. Stopped, stale and previous-run evidence
  produce explicit warnings. A historical successful GNN response cannot imply
  current freshness.
- Distinguish branch availability, completeness, sensor checks and joins.
  Incomplete responses display **GNN incomplete** and list specific health causes.
- Preserve current null scores and unscored reasons alongside each head's last
  valid score, timestamp and run identity. History charts preserve null gaps.
- Count the model's actual `status=ok` devices correctly. Warm-up displays both
  15-window and 60-minute requirements.
- Preserve all relationships from the retained five observations before browser
  permission filtering and the 36-group display limit. Report displayed/total
  matching groups, endpoint relationships, flows, capture range and run/session
  identities. Mixed permissions are explicit; grouped external self-loops are
  visible and inspectable. Reset filtering is available.
- Group repeated operational warnings, distinguish current and historical alerts,
  and filter before the 200-alert presentation limit. Original events remain intact.
- Show existing controller acceptance reports separately as archived engineering
  history. Four expired and two removed actions have retained outcomes. One old
  outage test lacks a terminal controller record and is explicitly labelled
  `historical_terminal_unrecorded`; traffic recovery is not converted into an
  invented controller outcome or packet/window join.
- Suppression creation/removal now retain audit entries atomically under a lock.
  Removal requires an operator and reason. Jayan chose to **keep controls locked**;
  the live token remains unset and the existing suppression ledger is unchanged.

## Validation and evidence

The full repository regression passes **103 Python tests**; focused integration
tests pass **26**, and the frontend checks pass **5**. The pre-change full baseline
was 92 (ML/network/integration alone collected 89). The existing PyTorch
future-deprecation warning remains.

All six pages were checked on desktop and at a 390 x 844 mobile viewport with
navigation transitions settled, no horizontal document overflow, and no browser
warnings/errors. Unknown-only, incomplete-window and stopped-runtime states were
verified. Mobile document content width is 375 px with its scrollbar.

Evidence directory on Saturn:

`/mnt/data/automud/live/acceptance/dashboard-continuation-20261020/`

- `tests.xml`, `focused-tests.xml`: final regression receipts.
- `history-15/observation-check.json` and `events-snapshot.jsonl`: three consecutive
  complete scored windows, 15 prior windows, source identities and event hash.
- `restarted/observation-check.json`: post-restart scoreable observation.
- `stopped-runtime.json`, `dashboard-stopped.jpg`: clean stop and operator view.
- `dashboard-desktop.jpg`, `dashboard-mobile.jpg`, `browser-verification.json`:
  final UI evidence.
- `protected-before.sha256`, `override-before.sha256`: protected configuration,
  model and live-control integrity baselines, checked after deployment.
- `source.sha256`, `evidence.sha256`: final deployed source and evidence hashes.

Recheck current observations without changing runtime, policies or model state:

```bash
cd /opt/automud/Auto-Mud
.venv-ml/bin/python -m integration.live.verify_observation \
  --output /mnt/data/automud/live/acceptance/UNIQUE-CHECK-ID \
  --minimum-windows 3 --minimum-history 15
```

`--minimum-history 15` checks the temporal history length; it does not claim the
separate one-hour full warm-up gate. Inspect the recorded `fully_warmed` and
`observed_age_seconds` values. The checker only accepts engineering/observe.

## Remaining work requiring separate evidence or decisions

1. Retain an uninterrupted one-hour run and verify `fully_warmed=true`. A restart
   begins a new session and resets this history.
2. Obtain a specifically approved isolated enforcement window. Persist a new
   packet/window-linked proposal, controller acceptance/barrier/install, measured
   traffic effect, expiry/revoke and recovery lifecycle. Historical action reports
   shown by the dashboard do not complete this end-to-end requirement. Normal
   observation must keep the controller engineering-action gate off.
3. Obtain an isolated maintenance window for persistence failure/backlog recovery.
   First prepare a dedicated queue and replay of retained engineering payloads;
   inject failure into that storage only, preserve pending bytes and order, restore
   writes/restart, and verify no loss or duplicate acceptance. Do not fill the host
   disk or fault the active service without explicit approval.
4. Obtain approved production inventory/binding authority, MUD/DNS policy,
   response/TTL/rollback authority, access and retention policy, and named owners.
   Access currently remains loopback behind SSH. Controls remain locked by choice.
5. Representative labelled model validation remains separate and would need
   explicit permission for any proposed dataset change. No such change is approved.
6. Repeat deployment-specific failure scenarios after any further sensor,
   controller or response changes; retain final evidence and obtain named sign-off.

Boot enablement has been configured, but an actual host reboot was not performed.

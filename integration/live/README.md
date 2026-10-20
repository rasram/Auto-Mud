# Saturn live pipeline

This package implements the continuous-window handoff around the supplied E1+Q
service. It persists each completed window before submission, evaluates a
separate versioned MUD permission branch, joins evidence on the exact session,
sensor, inventory and UTC minute, records decisions, and keeps enforcement in
observation mode by default.

The Saturn configuration is `configs/live/saturn.json`. Its deterministic MAC,
IP and switch-port map is the actual map used by `network.testbed.live_topology`.
The controller REST listener and OpenFlow listener bind to loopback. OS-Ken is
used as Ubuntu 24.04's packaged, maintained Ryu fork; the app retains a Ryu 4.34
import fallback for a separately qualified image.

On the configured Saturn host, `automud-testbed.service` now supervises the
engineering topology and Zeek. Jayan approved boot auto-start on 20 October.
Use `sudo systemctl status automud-testbed` to inspect it and `sudo systemctl
stop/start automud-testbed` for deliberate maintenance. Do not launch a second
topology while it is running. The unit is supplied in `configs/live/`.

`--no-cli` with no duration runs until SIGTERM/SIGINT and cleans up its own
topology. Optional `--engineering-traffic` starts low-rate probes for the existing
six local MUD permissions plus a deliberate denied ring across the existing
twelve devices. It refuses operation outside engineering/observe. These probes
are not training data, representative normal traffic or accuracy evidence.

See the [20 October record](../../docs/dashboard/SATURN_DASHBOARD_CONTINUATION_20261020.md)
for read-only observation verification, receipts and unresolved acceptance gates.

Start the controller, then the isolated lab:

```bash
sudo systemctl start automud-controller
curl --fail http://127.0.0.1:8080/v1/switches
sudo /usr/bin/python3 -m network.testbed.live_topology \
  --config configs/live/saturn.json
```

The launcher creates `s1` only when that bridge is absent, uses OpenFlow 1.3 and
secure fail mode, attaches a dedicated mirrored sensor, disables host offloads,
starts Zeek in the sensor namespace and writes the actual runtime inventory to
`/mnt/data/automud/live/runs/<run-id>/runtime.json`. It cleans up only its own
Mininet network when it exits.

Run the finalizer after a complete UTC minute. The telemetry and health paths
are recorded in `runtime.json`:

```bash
source /opt/automud/activate.sh
python -m integration.live.finalizer \
  --config configs/live/saturn.json \
  --telemetry /mnt/data/automud/live/runs/RUN/zeek/automud-window.log \
  --health /mnt/data/automud/live/runs/RUN/zeek/automud-health.log \
  --run-id RUN --session-id RUN --daemon
```

The finalizer sends unhealthy evidence when health is missing, persists pending
payloads under a run-isolated `/mnt/data/automud/live/queue/runs/<token>/pending`
directory, retries identical bytes, and stores accepted joined results separately.
The persistent service follows `current.json` when a new topology run starts and
stops at the recorded run boundary. Events are appended with `fsync` to
`/mnt/data/automud/live/events.jsonl`.

The read-only dashboard listens on `127.0.0.1:8090` and exposes `/api/status`,
`/api/events` and `/api/traces`. Build an evidence-linked acceptance receipt
after a run with:

```bash
python -m integration.live.acceptance \
  --config configs/live/saturn.json \
  --runtime /mnt/data/automud/live/runs/RUN/runtime.json \
  --tests-junit /mnt/data/automud/live/acceptance/RUN/tests.xml \
  --action-run ACTION_RUN \
  --output /mnt/data/automud/live/acceptance/RUN
```

The receipt marks unperformed disruptive scenarios and missing team approvals as
blocked. It never turns unit coverage into a live deployment sign-off.

`observation_kind` is `engineering` and `decision.mode` is `observe` in the
committed Saturn config. These two independent gates prevent the controller
from receiving actions during qualification. Enabling live enforcement requires
a reviewed live inventory/policy, successful failure tests, and changing both
values deliberately.

# Local AutoMUD environment and v2 A/B experiment

The dedicated WSL 2 distribution is `automud`. Its virtual disk is stored under
`C:\Users\Jayan\WSL\automud\distribution`. The main source project remains
`C:\Users\Jayan\Coding\Projects\Auto-Mud`; its Linux execution copy is
`/home/jayan/Auto-Mud`. Synchronize changed source files before collecting data.
The two Python environments are separate; never copy a Windows venv into Linux.

Installed inside this distribution: Ubuntu 24.04, Mininet, Open vSwitch,
tcpdump, ethtool, mergecap, Zeek 8.0, and `.venv` with CUDA PyTorch/PyG.
The exact Python versions are recorded in `.venv/installed-requirements.txt`.
No Neo4j or Ryu is required for collection. Do not install Linux NVIDIA drivers;
the WSL GPU is supplied by the Windows driver.

## Open and verify

From PowerShell:

```powershell
wsl -d automud --cd /home/jayan/Auto-Mud
```

Inside that shell:

```bash
source .venv/bin/activate
zeek --version
sudo ovs-vsctl show
python -c 'import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))'
```

This imported distribution has a normal `jayan` user without a preset password.
To establish one for interactive sudo, use `wsl -d automud -u root --exec passwd jayan`
from PowerShell. Background collection launched during setup uses an explicit
root WSL invocation; no passwordless sudo rule is installed.

## Monitor the experiment

From PowerShell in the Windows project:

```powershell
.\scripts\gnn_progress.ps1
.\scripts\gnn_progress.ps1 -Watch
.\scripts\gnn_progress.ps1 -Json
```

Or directly inside WSL:

```bash
.venv/bin/python scripts/gnn_progress.py
tail -n 30 data/gnn/local-v2-run/pipeline.log
```

Progress reports the phase, completed captures, epoch, GPU, maximum-epoch ETA,
completion or failure. ETA includes an upper estimate for the epoch limit;
early stopping may shorten training. A paused conversation does not pause the
background job. Keep Windows awake and do not shut down WSL while it runs.
The status command does not resume or restart failed training.

The experiment runs as the `automud-v2-training` systemd service. Inspect it with
`systemctl status automud-v2-training`. A Windows WSL keep-alive process maintains
the distribution while the job runs. Stopping the job is separate from pausing
this conversation; interrupted training is not automatically checkpoint-resumed.

## Input schema changes

`automud.graph.v2` has **38 measured features and a 99-dimensional input**:
38 normalized features + 3 time/activity columns + 12 node types + 8 service
categories + 38 availability masks. The complete order is exported to
`configs/gnn/schemas/features.json`. V1 checkpoints are incompatible with v2;
keep their reports and models as historical artifacts rather than mixing them.
V1 manifests and canonical V1 Zeek interval telemetry can be rebuilt into v2.

The first 18 features retain their original meaning. The additional features are
local/external directional byte totals; external and service flow fractions;
bytes per initiated flow; connection gap mean, coefficient of variation and
minimum; maximum new-flow count per fixed 10-second bin; preceding 5/15-minute
traffic averages; log traffic changes; and 15-minute connection-gap variation.
Rolling averages exclude the current window. Gap variation may include events
observed within the current window and previous windows, never future events.
History starts empty at a session boundary and resets during an observation
outage. Masks identify insufficient timing/history observations. A rolling mean
includes idle minutes, not just active minutes. Use the exact same builder live.

Required measured telemetry: UTC minute window, UID, original/responding addresses,
protocol, destination port, connection start timestamp, directional IP-byte and
packet deltas, observed duration, established/failed flags and new-flow flag.
Preserve PCAPs, labels, inventory IP/MAC leases, manifests, extraction policy
hashes and tool versions. Capture loss or an incomplete interval invalidates
training. Re-extract raw PCAPs if these fields are missing; aggregated old graphs
cannot recover discarded information.

External connections now produce observed **service context nodes**, grouped by
port/protocol category, not raw IP or device identifiers. Categories are DNS,
web, TLS-port, NTP, discovery, messaging, other TCP, and other UDP. Port categories
are hints, not application identification: generated traffic on port 443 is not
necessarily actual TLS. External context nodes participate in message passing
and link scoring but are never classified/reconstructed as IoT devices. This
extends Head B to initiated external service relationships. It does not identify
individual cloud servers or establish destination authorization; profiling/MUD
remains responsible for that separate signal.

## Labels and collection design

The actor `label` retains Head C compromised-device semantics. `behavior_label`
is Head A truth; `relationship_label` is Head B truth. Victims receiving planned
scan/lateral traffic have behavioral interval annotations while remaining
non-compromised actors. These are controlled-plan annotations, not proof that
a real victim became infected. Exfiltration/beaconing over permitted service
categories are Head A positives and Head B negatives in this experiment.
Unknown/boundary observations are excluded, not silently called benign.

Revised plans include legitimate polling and bursty uploads for all twelve
devices, plus varied attack/control timing, rates, volumes and services. Attack
and control services overlap: no dedicated attack port or destination is used.
These added activities are documented simulation assumptions, not measured
application traces or guaranteed realistic malware. Cases invisible at this
observation level remain fundamentally ambiguous.

The default local run rebuilds the existing seven-day normal telemetry into v2,
adds 96 revised **clean control** sessions, and evaluates 96 independent revised
attack/control runs, all twenty minutes each. Seeds 11/13/17 controls train;
seed 19 from-start controls validate; seed 19 later controls calibrate;
seed 29/31 attack/control pairs test after checkpoint freezing. Seeds alone are
not evidence of generalization to new devices or scenario families. This is a
development simulation, not a final real-network benchmark or a validated
minimum data volume. Actual active-window coverage is saved in
`development-coverage.json`. Increase diversity based on learning curves and
fresh-session confidence intervals, not repeated deterministic windows.

## Model and results

GraphSAGE consumes the expanded schema. Its reconstruction encoder retains the
robust revision's residual self path, normalization, gated neighborhood messages,
feature denoising and bounded inputs. The link encoder retains stable type and
service context rather than traffic volumes. Each queried relationship is removed
in both directions before scoring. Head C additionally masks rolling/history
features to avoid cold-start artifacts, but is not trained in this A/B experiment.

Fit the scaler on clean training only; select A/B thresholds on clean calibration
only. Frozen-test metrics report behavioral/relationship labels, coverage,
per-family scores, and a separate compromised-actor diagnostic. Do not compare
new A/B labels directly with the previous actor-only headline scores.
No improved accuracy is guaranteed by a schema or a training quality gate.

Outputs under `data/gnn/local-v2-run`: plans, PCAP/Zeek capture directories,
sources, prepared graph JSONL/catalog, model/checkpoints/losses, normal-test report,
and frozen attack-control `evaluation.json` plus predictions. The main experiment
is virtual packet time. A real Mininet pilot validates infrastructure separately;
passing that pilot does not establish real attack-detection performance. Use
`network.testbed.collect` for real collection, not the legacy topology replay.

The existing COLLECTION.md command flow still applies after updated plans and
schema are installed. Use new directories; do not overwrite historical datasets.

## Remove the environment later

First copy needed captures/results out of the distribution. Then, from PowerShell:

```powershell
wsl --terminate automud
wsl --unregister automud
```

Unregistering deletes the distribution's Linux files. It does not remove files
already saved in the Windows project. WSL remains installed for other distributions.

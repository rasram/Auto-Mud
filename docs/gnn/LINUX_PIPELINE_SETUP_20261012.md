# AutoMUD supervised E1+Q pipeline setup on Linux

Updated 18 October 2026. This guide installs **original E1+Q**, bundle
`supervised-E1Q-20261018` (seed 42, epoch 5, frozen Q cutoffs). Only the model
and required loader change from C. Features, frozen preprocessing, service
configuration and pipeline procedures remain unchanged. Publishing this
repository does not activate an existing host.

The ML service is supplied. Continuous acquisition/finalization, MUD, the
Decision Engine and Ryu enforcement still need integration. Follow the ordered
steps in [the live handoff](LIVE_PIPELINE_HANDOFF_20261012.md) after these checks.

## 1. Obtain the complete current package and choose the lab inventory

Use a dedicated Linux lab host or VM. Ubuntu 24.04 / Python 3.12 is the reference
userspace. The qualified WSL2 environment has Mininet 2.3.0, OVS 3.3.9 and Zeek
8.0.10. A fresh native Linux deployment must pass these checks on its own host.

Copy or check out the complete current repository snapshot, including:

| Location | Required contents |
|---|---|
| `models/gnn/` | `detector.pt`, `normalizer.json`, `flow-profiles.json`, `thresholds.json`, `feature-contract.json`, `results.json`, `manifest.json` |
| `ml/` | Inference, supervised adapter, rolling features/history, HTTP server/client |
| `configs/gnn/live/` | Input/output schemas, service config, inventory example, systemd template |
| `configs/gnn/schemas/supervised/` | Internal ordered supervised feature contract |
| `fixtures/gnn/` | Small consumed installation reference, including causal history |
| `network/` | Mininet/testbed tools and project Zeek policy |

Until this replacement is committed, cloning the old commit alone does not
supply the new package. Full datasets, training code and private notes are not
runtime dependencies. Do not copy another machine's virtual environment.

For the authored 12-device household, start from
`network/testbed/topology-supervised.json` and
`configs/gnn/live/inventory.example.json`. They retain the profile's stable
device IDs/types and example IP mapping, including LiFX and Netatmo Welcome.
The older `topology.json` has a different cohort/order/IP mapping. Choose the
supervised template explicitly when preparing new traffic. After installing the
host tools, inspect `python3 network/testbed/run_full_topology.py --help`.
That collector accepts `--topology network/testbed/topology-supervised.json`;
its traffic directory must contain matching devices. It is a standalone
collection launcher, not the finished controller-managed deployment.
Do not relabel an unrelated device to borrow a profile. Populate actual MACs
and UTC lease bounds at runtime. Align MUD rules and controller targets to the
same inventory. Authored traffic edges do not grant MUD permission.

## 2. Install and check host networking tools

From the dedicated Ubuntu host:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl ca-certificates \
  gnupg mininet openvswitch-switch tcpdump ethtool iproute2 iputils-ping
sudo systemctl enable --now openvswitch-switch
mn --version
ovs-vsctl --version
sudo ovs-vsctl show
sudo mn --switch ovsbr --test pingall
```

Run the connectivity test only when no other Mininet job owns the lab. It checks
standalone forwarding. Mininet needs network privileges; the ML service runs as
an ordinary user. VMs need namespaces, veth and the OVS kernel datapath.
[Official Mininet installation](https://mininet.org/download/).

## 3. Install Zeek and use the project minute policy

Start with the qualified 8.0 series. For Ubuntu 24.04:

```bash
curl -fsSL \
  https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/automud-zeek.gpg > /dev/null
echo 'deb [signed-by=/usr/share/keyrings/automud-zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/automud-zeek.list
sudo apt update
sudo apt install -y zeek-8.0
export PATH="/opt/zeek/bin:$PATH"
zeek --version
```

Check distribution/package availability against the
[official Zeek installation instructions](https://docs.zeek.org/en/current/install.html).
Record actual versions; upgrades require the acceptance checks below.

Load `network/zeek/automud-window.zeek`. It emits directional minute IP-byte/
packet deltas and causal flow outcomes. Ordinary `conn.log` lifetime totals
have different semantics. For live Mininet, launch Zeek inside the sensor host's
namespace with absolute binary/policy paths, its actual interface and a writable
log directory. Confirm both directions, drops, offloads and duplicate counting.
Do not use a blanket checksum bypass to conceal capture errors.

The team must add a continuous interval finalizer: packet arrival alone does
not finalize healthy silent minutes. See handoff steps 3–4.

## 4. Install the ML environment

Assume the package is in `$HOME/Auto-Mud`; substitute its actual path:

```bash
cd "$HOME/Auto-Mud"
python3 -m venv .venv-ml
source .venv-ml/bin/activate
python -m pip install --upgrade pip
python -m pip install 'torch==2.14.1' \
  --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements-ml-runtime.lock.txt
python -m pip check
```

The lock records six qualified top-level versions, not a hashed transitive
lock or guaranteed wheel availability on every platform. The reference Torch
is `2.14.1+cu130`, exercised on CPU; the local CUDA suffix is omitted for
CPU-wheel selection. If the official CPU index cannot supply that version for
your platform, qualify an available official compatible release in a separate
environment and record its versions after all checks pass. Do not silently unpin.
[PyTorch installation](https://pytorch.org/get-started/locally/),
[PyG installation](https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html).

Use `configs/gnn/live/runtime-qualification.json` for the recorded environment.
WSL and a GPU are optional. No training stack is needed. Keep Ryu and web/MUD
dependencies in separate environments. After acceptance save `pip freeze`,
OS/kernel information and the deployment configuration.

## 5. Verify the supervised release

```bash
python -m ml check-model --bundle models/gnn --device cpu
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
python -m pytest ml/tests network/tests -q
```

Expected model check: `status=ok`, `verified_files=6`. The manifest binds the
joint checkpoint and its five companion assets. Do not edit hashes to bypass
integrity errors.

Expected fixture: `passed`, **9 graphs, 108 household records, 216 matching
A/B flags**, absolute score error at most `1e-4`, no training or new evaluation
data. Packaging reproduced both scores with zero CPU error. Cold and continuous
examples include their exact causal prior graphs. This is an installation check;
do not tune thresholds on it. The current regression suite has **74 passing Linux tests**.

Optional prediction check (choose a fresh output path):

```bash
python -m ml predict --bundle models/gnn --graphs fixtures/gnn/graphs.jsonl \
  --out tmp/supervised-fixture-predictions.jsonl --device cpu
```

Do not send old v4 model graphs directly to the supervised model. The live service builds the new
61-feature inputs and 15-minute causal neural history internally. For a finite
capture, `build-graphs --bundle models/gnn` uses the supervised adapter.

### Existing C service: model-only upgrade

Keep the active C directory and its state intact. Export the approved E1+Q
bundle to a new immutable path before staging; never replace bytes referenced
by durable state. Obtain this release in a separate checkout rather than pulling
over a running service's bundle directory. The deployment owner coordinates the
runtime/adapter cutover while keeping the existing active/previous paths intact.
Follow [the existing lifecycle API](LIVE_GNN_API.md#5-safe-model-replacement-and-rollback).
The same profile/adapter retains causal raw history and recomputes GRU states;
cached retries keep their original C provenance. The complete rollback is
`models/gnn-c-20261016` with fixture `fixtures/gnn-c-20261016`.
The runtime-qualification config records the earlier Linux environment;
[DEPLOYMENT_VALIDATION.json](DEPLOYMENT_VALIDATION.json) records this E1 release.

## 6. Migrate an existing New 2 deployment

Stop the old service and its sender. Back up the **old model directory and
matching state/config together** before replacing files. Preserve them in a
separate version directory if historical rollback is required.

Install the complete new source and E1+Q bundle. Use the updated
`configs/gnn/live/service.json`, whose state path is
`tmp/gnn-live-supervised/state.json`. Start a fresh supervised session/state:
do not copy New 2 state over this path or edit its bundle ID. Restoring a state
file that points at overwritten model bytes is rejected. Update any custom
service `ReadWritePaths` and monitoring paths too.

Pass step 5, then start the new service and sender. Expect cold-start history.
Later supervised restarts restore their own accepted windows/history normally.
Old residual scores, thresholds and dashboards must not be reused as supervised logits.

## 7. Start the supervised evidence service and check transport

```bash
python -m ml serve --config configs/gnn/live/service.json
```

The launcher prints a ready event and listens on `127.0.0.1:8001`. It loads E1+Q
once and owns one durable state file. Ctrl+C releases its lock. In another
terminal with the same ML environment:

```bash
curl --fail http://127.0.0.1:8001/readyz
curl --fail http://127.0.0.1:8001/v1/model
python -m ml sample-window --out tmp/supervised-engineering-window.json
python -m ml submit-window --request tmp/supervised-engineering-window.json \
  --out tmp/supervised-engineering-evidence.json
```

Choose fresh file names on repeat. The example has `observation_kind=engineering`;
exclude it from enforcement. Model version must be `supervised-E1Q-20261018`.
Both checkpoint hashes identify the same joint `detector.pt`.

Input `automud.live-window.v1` and output `automud.gnn-evidence.v1` remain stable.
A is behavioral/affected-device evidence; B concerns initiated relationships.
Scores are raw supervised logits, possibly negative, with strict frozen cutoffs
A `0.7624336779117584`, B `4.921021908521652`. Use returned flags/provenance.
They are not probabilities or MUD permissions. B is null without an observed
initiated relationship; idle/unavailable scores remain null. E1 enables
directed learned neighbor messages and retains the same own-device history.

Supply actual completed UTC minutes, stable inventory, health and watermarks;
no labels, private source provenance or tensors. Healthy silence is an empty
minute with verified capture health; failed observation is unavailable.
Known profile identities are listed in the inventory example. Unknown devices
can be scored with missing-profile masks and type/global normalization, but
their accuracy is unverified. `profile_support.known_device` exposes support.

For authenticated operation, export `AUTOMUD_GNN_API_TOKEN` in service/client
shells. Set a separate `AUTOMUD_GNN_ADMIN_TOKEN` only for operators needing
model/reset routes. With tokens, health requests need
`-H "Authorization: Bearer $AUTOMUD_GNN_API_TOKEN"`. Non-loopback binding
requires an API token; use a trusted lab network or TLS proxy. No admin token
disables administration. See [the API guide](LIVE_GNN_API.md).

Config paths resolve against `project_root=../../..`. Defaults: CPU/one Torch
thread, eight streams/connections, 4 MiB requests and 16 MiB durable state.
Keep active/previous bundle directories immutable and accessible. Readiness
checks ML; monitor sensor health and stream freshness separately.

### Optional systemd service

The template expects `/opt/automud/Auto-Mud` and a fresh `.venv-ml` there.
Complete steps 4–5 at that path first. Create the account only if absent:

```bash
sudo useradd --system --user-group --home-dir /opt/automud --no-create-home automud
sudo install -d -o automud -g automud -m 0750 /opt/automud/Auto-Mud/tmp/gnn-live-supervised
sudo install -d -m 0750 /etc/automud
```

Allow the account to read/traverse code, models and venv; only state needs write
access. If using tokens, create root-readable `/etc/automud/gnn.env` (mode 0600)
with the two environment variables as appropriate. Keep secrets out of Git.
Stop any foreground instance, then:

```bash
sudo install -m 0644 configs/gnn/live/automud-gnn.service /etc/systemd/system/automud-gnn.service
sudo systemctl daemon-reload
sudo systemctl enable --now automud-gnn
sudo systemctl status automud-gnn
sudo journalctl -u automud-gnn -n 50 --no-pager
```

`ProtectHome=true` prevents using a venv under a home directory. Change all
absolute paths and `ReadWritePaths` together if relocating. The template has not
been enabled by this handoff. A host without systemd can use its process manager.

## 8. Reproduce packet-to-supervised-API acceptance

Use fresh output directories, from the repository. Only Mininet needs root/system
Python; extraction/inference use the ordinary ML environment:

```bash
sudo /usr/bin/python3 -m network.testbed.gnn_acceptance --out tmp/gnn-supervised-lab/capture
python -m ml validate-live-capture --capture-dir tmp/gnn-supervised-lab/capture \
  --out tmp/gnn-supervised-lab/validation --zeek /opt/zeek/bin/zeek
python -m ml benchmark-live --out tmp/gnn-supervised-lab/throughput --windows 60 --devices 12
```

The helper reserves `amgnn0`, refuses an existing bridge/output and cleans only
its own network. It takes roughly 1–2 minutes and needs no Ryu/NAT/internet.
Ensure the ordinary user can read the capture if sudo's umask restricts it.

Require `validation/report.json` to pass: zero capture drops, at least 16
controlled closed-port rows, exact features/edges and matching flags/scores,
durable restart, identical retries and stage/activate/rollback. It starts a
temporary localhost API. The synthetic 12-device capacity probe must keep up
with a 60-second cadence; size your deployment from its own measurements.
These are engineering checks, not live detection accuracy. Recorded release
evidence is [DEPLOYMENT_VALIDATION.json](DEPLOYMENT_VALIDATION.json).

## 9. Qualify Ryu separately and connect controller-managed OVS

Ryu's [upstream repository](https://github.com/faucetsdn/ryu) states that it is
not currently maintained. Anand must supply a tested, pinned controller
environment/image and pass import/startup, switch connection and rule checks.
Do not install it into `.venv-ml` or assume Python 3.12 compatibility. There is
no accepted controller lock or AutoMUD action app in this handoff.

Use Mininet `OVSSwitch`/`RemoteController`, OpenFlow 1.3 and an intentional
fail mode. The old standalone `OVSBridge` collectors do not become
controller-managed just because ML changed. On the lab's actual `s1`:

```bash
sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13
sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6653
sudo ovs-vsctl list Controller
sudo ovs-ofctl -O OpenFlow13 show s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Use a reachable controller address if it runs in another namespace/host.
Discover the dedicated sensor port; the example below must be replaced with it:

```bash
automud_sensor_port=s1-eth13
sudo ovs-vsctl -- --id=@p get Port "$automud_sensor_port" \
  -- --id=@m create Mirror name=automud select-all=true output-port=@p \
  -- set Bridge s1 mirrors=@m
sudo ovs-vsctl list Mirror
```

Make mirror setup idempotent and reserve its output port for observation.
[OVS mirroring documentation](https://docs.openvswitch.org/en/latest/faq/configuration/).
Confirm bidirectional visibility and intended MUD baseline forwarding.

## 10. Complete the full pipeline in order

Follow [handoff steps 1–12](LIVE_PIPELINE_HANDOFF_20261012.md#remaining-work-follow-these-steps-in-order):
inventory/configuration, controller-managed testbed, sensor finalizer, E1+Q evidence,
MUD evidence, timed join, Decision Engine observation, scoped action/expiry,
failure recovery, timing/events and host sign-off.

The supplied model is usable for live evidence. Full enforcement readiness
requires those team checks. Its consumed benchmark results and A recall
tradeoff are disclosed in [MODEL_RESULTS.md](MODEL_RESULTS.md).
An installation fixture or software parity check does not establish accuracy
on new live traffic.

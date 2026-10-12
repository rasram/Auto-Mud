# GNN-only AutoMUD setup on native Linux

This guide installs and checks the selected New 2 native-clock/context A and
original frozen B. Native Linux is suitable; WSL is not required. The GNN service is supplied and qualified on Linux/WSL. Teammates finish sensor finalization, MUD, the Decision Engine and controller described in [the handoff](LIVE_PIPELINE_HANDOFF_20261012.md).
Use a dedicated Linux lab host/VM for Mininet networking commands.

## 1. Reference environment and package contents

Ubuntu 24.04 LTS / Python 3.12 is the first target, matching current working
userspace. The reference WSL environment has Mininet 2.3.0, OVS 3.3.9 and Zeek
8.0.10 at `/opt/zeek/bin/zeek`. Native-Linux end-to-end deployment remains untested.
CPU inference is supported; a GPU is not required for installation/integration.

The shared package contains:

- `models/gnn/`: `selected-a.pt`, `frozen-b.pt`, manifest and numeric results.
  Scaler, residual references and saved thresholds are included in the checkpoint.
- `ml/`: inference-only runtime, canonical extraction, graphs and tensor utilities.
- `configs/gnn/schemas/`: selected v4 contract plus B's required v3 contract.
- `fixtures/gnn/`: small consumed graphs and expected outputs for installation tests.
- `configs/gnn/live/`: frozen external schemas, service config and optional systemd template.
- Selected screenshot/results, setup/handoff/API guides and compact deployment validation under `docs/gnn/`.

Full datasets, previous models, conversation notes, investigations and development
scripts are excluded from Git. None is a live inference dependency. A fixture is
also not a live dependency; it is included to check model loading and outputs.
Do not copy another machine's `.venv`. Until changes are committed, Jayan must
transfer the current source/package snapshot: cloning the old commit is insufficient.

## 2. Host tools

From a dedicated Ubuntu 24.04 host:

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

Mininet supports native Ubuntu/Debian and needs network privileges. Run the
connectivity test only when no other Mininet job owns the lab. It tests standalone
forwarding, not the controller or MUD policy. Keep the ML service unprivileged.
[Official Mininet installation](https://mininet.org/download/).
If systemd is absent, use the distribution's OVS service method. A VM must support
network namespaces, veth and the OVS kernel datapath.

## 3. Zeek with the project policy

Use the 8.0 LTS line first and verify feature parity after patch upgrades. For
Ubuntu 24.04, configure a repository-specific key and official package source:

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

Use the matching distribution repository on other Linux versions. Persist PATH
in service configuration or use `/opt/zeek/bin/zeek` explicitly.
[Official Zeek installation](https://docs.zeek.org/en/current/install.html).

Load `network/zeek/automud-window.zeek`. It produces minute directional IP-byte/
packet deltas and causal flow metadata; ordinary connection totals are unsuitable.
On live Mininet traffic run Zeek **inside the sensor host namespace** using the
host's `popen`/`cmd` or Mininet CLI host command. Find its actual interface and use
absolute binary/policy paths and a writable log directory. Validate drops,
offloads, bidirectional visibility and duplicate counting. Do not use a blanket
checksum bypass to hide capture errors. Add a live interval finalizer for silence,
completion and partial shutdown; it is not implemented by the offline extractor.

## 4. ML environment

Assume the current package is in `$HOME/Auto-Mud`; substitute your actual path. Use the ML-only pinned top-level versions, not root requirements that mix ML/controller/web dependencies:

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

`requirements-ml-runtime.lock.txt` records the six top-level versions qualified by the existing Linux/WSL tests. It is not a fully hashed transitive lock or proof that every pinned wheel is available for every platform. Actual tested Torch is `2.14.1+cu130`, run on CPU; the upstream version is pinned without the CUDA-local suffix for CPU-wheel selection. If the CPU index cannot supply that version for your platform, do not silently unpin: use an available official compatible release in a separate environment, pass section 5 and the live acceptance checks, and record that deployment's versions. [Official PyTorch installation](https://pytorch.org/get-started/locally/), [PyG installation](https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html).

Recorded reference environment: `configs/gnn/live/runtime-qualification.json` (Python 3.12.3, Ubuntu 24.04 userspace, WSL2 x86_64). WSL is not a runtime dependency. A fresh native-host install must pass the same checks. No SciPy/scikit-learn training stack is required by the inference package, and a GPU is optional. Do not copy another machine's virtual environment.

After successful acceptance, save `python -m pip freeze`, OS/kernel information and your config in the deployment's operational records. Preserve the wheel-index instructions. Root requirements and Ryu belong to separate environments.

## 5. Required installation tests — no full dataset needed

First verify all bundle hashes, selected operating point and embedded B integrity:

```bash
python -m ml check-model --bundle models/gnn --device cpu
```

Expected: `status=ok`, `verified_files=3`. This loads the models without scoring.
The manifest is additional metadata; its three verified inputs are the two
checkpoints and results file. Do not modify hashes to bypass a mismatch.

Then check model loading **and inference output** against the public reference:

```bash
python -m ml check-fixture --bundle models/gnn --fixture fixtures/gnn --device cpu
python -m pytest ml/tests network/tests -q
```

Expected fixture result:

- `status=passed`, 20 graphs, 394 device/window records, 788 matching A/B flags.
- Absolute score differences no larger than `1e-4`.
- `training_invocations=0`, `new_evaluation_data=false`.

The same CPU check passed during packaging: maximum errors A `7.8831e-6`,
B `1.5259e-5` against saved CUDA outputs. The graphs and trimmed expected outputs
total about **1.17 MB**. This checks installation/reproduction, not live accuracy
or the aggregate metrics in the screenshot. It contains no full research dataset
and should never be used to tune thresholds. Run it when dependencies change.

Optional CLI reproduction into a fresh output path:

```bash
python -m ml predict --bundle models/gnn --graphs fixtures/gnn/graphs.jsonl \
  --out tmp/gnn-fixture-predictions.jsonl --device cpu
```

The output guard refuses overwriting a previous file. Do not run old training or
research-final commands as setup prerequisites; they are not in this package.
After acceptance, record `python -m pip freeze` and OS/kernel information with
the deployment configuration. Preserve CPU wheel-index instructions beside the lock.

## 6. Run the supplied live GNN service

From the repository with `.venv-ml` activated:

```bash
python -m ml serve --config configs/gnn/live/service.json
```

The foreground launcher prints a ready event and serves `127.0.0.1:8001`. It loads the bundle once. Ctrl+C closes the listener/state lock; restart restores accepted history and active/previous bundle pointers. Default durable state is `tmp/gnn-live/state.json`; do not share it between service instances. Start as an ordinary user with read access to code/models and write access to the state directory.

In another terminal:

```bash
cd "$HOME/Auto-Mud"
source .venv-ml/bin/activate
curl --fail http://127.0.0.1:8001/readyz
curl --fail http://127.0.0.1:8001/v1/model
python -m ml sample-window --out tmp/gnn-engineering-window.json
python -m ml submit-window --request tmp/gnn-engineering-window.json \
  --out tmp/gnn-engineering-evidence.json
```

Choose fresh output names when repeating file-producing commands. The example is explicitly `observation_kind=engineering`; it tests the API and must not trigger enforcement. It has its own engineering stream. The installation fixture checks the selected model's expected numeric outputs; this example checks transport. The qualified regression suite has **45 passing tests**, including actual CLI startup/shutdown/restart. [Deployment validation](DEPLOYMENT_VALIDATION.json).

Configure `configs/gnn/live/service.json` for your installation. `project_root=../../..` resolves relative to the config directory; other file paths resolve against that root. Defaults are CPU/one Torch thread, eight streams/connections, a 4 MiB request and 16 MiB state. See [API limits and semantics](LIVE_GNN_API.md). Keep active/previous bundle directories intact and the state directory writable.

For token-protected operation, set the same API token in the service and client shells. Set an independent admin token in the service/operator shells only if model/reset operations are needed:

```bash
read -rsp 'GNN API token: ' AUTOMUD_GNN_API_TOKEN
printf '\n'
export AUTOMUD_GNN_API_TOKEN
read -rsp 'GNN administrator token: ' AUTOMUD_GNN_ADMIN_TOKEN
printf '\n'
export AUTOMUD_GNN_ADMIN_TOKEN
python -m ml serve --config configs/gnn/live/service.json
```

Authenticate health requests with `curl --fail -H "Authorization: Bearer $AUTOMUD_GNN_API_TOKEN" http://127.0.0.1:8001/readyz`. The submit command reads its API token from the environment. A non-loopback listener requires an API token; configure the orchestrator URL accordingly and use a trusted lab network or TLS proxy. No admin token disables administrator endpoints. Readiness only checks the ML service; check stream freshness/capture health separately.

### Optional systemd operation

`configs/gnn/live/automud-gnn.service` is a template, not an installed service. It expects a current source snapshot in `/opt/automud/Auto-Mud` with a fresh `.venv-ml` installed there. Complete sections 4–5 at that path before enabling it. `ProtectHome=true` intentionally prevents using a venv under a user's home directory. Adapt all absolute paths and `ReadWritePaths` together if choosing another location.

On that host, create an unprivileged service account and state directory:

```bash
sudo useradd --system --user-group --home-dir /opt/automud --no-create-home automud
sudo install -d -o automud -g automud -m 0750 /opt/automud/Auto-Mud/tmp/gnn-live
sudo install -d -m 0750 /etc/automud
```

Create the account only if it does not already exist. Ensure it can traverse/read the installed code, venv and models; only state needs write permission. If tokens are used, create root-readable `/etc/automud/gnn.env` with the appropriate `AUTOMUD_GNN_API_TOKEN=...` and optional `AUTOMUD_GNN_ADMIN_TOKEN=...`; set mode `0600`. Do not put secrets in Git or this template. Then:

```bash
sudo install -m 0644 configs/gnn/live/automud-gnn.service /etc/systemd/system/automud-gnn.service
sudo systemctl daemon-reload
sudo systemctl enable --now automud-gnn
sudo systemctl status automud-gnn
sudo journalctl -u automud-gnn -n 50 --no-pager
```

Stop the foreground instance before enabling systemd. The shared template has not been installed/enabled by this handoff. Hosts without systemd can use the qualified foreground launcher under their process manager.

### Reproduce sensor-to-model acceptance on your lab host

After host tools and Zeek are installed, create a fresh isolated lab capture. Run from the repository; only the Mininet helper needs root/system Python. The helper reserves bridge `amgnn0`, refuses an existing bridge/output path and cleans only its own network. It has no Ryu/NAT/internet requirement and takes roughly 1–2 minutes:

```bash
sudo /usr/bin/python3 -m network.testbed.gnn_acceptance --out tmp/gnn-live-lab/capture
python -m ml validate-live-capture --capture-dir tmp/gnn-live-lab/capture \
  --out tmp/gnn-live-lab/validation --zeek /opt/zeek/bin/zeek
python -m ml benchmark-live --out tmp/gnn-live-lab/throughput --windows 60 --devices 12
```

The ordinary ML process needs read access to the capture; adjust permissions if your sudo umask restricts access. Validation extracts canonical Zeek rows, compares streaming/offline features/edges/scores, tests HTTP replay, staging/activation/targeted rollback and durable restart. It runs its own temporary localhost API, not your deployed service. Expected report: `status=passed`, zero drops and score error, exact feature/edge parity, at least 16 controlled closed-port rows. The workload benchmark uses synthetic engineering observations and measures CPU/API capacity; neither command computes accuracy or trains. Raw captures/temporary candidates belong in ignored `tmp/`, not the teammate model bundle.

The orchestrator must still implement actual continuous Zeek acquisition and an interval finalizer, using the schema in [the API guide](LIVE_GNN_API.md). Supply genuine UTC timestamps/leases, ordered completed windows and honest sensor health, including healthy silent minutes and unavailable intervals. The service owns clock/features/history; teammates do not build model tensors or invent native-source provenance.

## 7. Ryu environment and OVS connection

Ryu is not installed in the verified ML environment. Its upstream currently says
it is not maintained. Qualify a separate controller Python/dependency environment
or provide a tested controller image; do not install Ryu in `.venv-ml` or assume
its dependencies work on Python 3.12. A controller substitution requires a team
decision. [Official Ryu repository](https://github.com/faucetsdn/ryu).

There is no accepted Ryu lock in this handoff. Anand must pin the working Python,
Ryu and supporting versions and pass `ryu-manager --help`, switch connection and
rule-installation checks. In that qualified environment, the built-in
`ryu.app.simple_switch_13` is a connectivity-only test; the AutoMUD action app still
needs implementation.

Configure the live launcher with `OVSSwitch`/`RemoteController`, OpenFlow 1.3 and
an intentional fail mode. The existing `OVSBridge` standalone collectors are not
the live enforcement launcher. On the dedicated lab's created `s1` bridge:

```bash
sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13
sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6653
sudo ovs-vsctl list Controller
sudo ovs-ofctl -O OpenFlow13 show s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Use `127.0.0.1` only when OVS and Ryu share the host network namespace. Otherwise
use the reachable controller address. Agree protocol/port on both ends.
[OVS OpenFlow documentation](https://docs.openvswitch.org/en/latest/faq/openflow/).

Create a dedicated sensor link and discover its actual switch port. Example:

```bash
automud_sensor_port=s1-eth13  # Replace with the discovered sensor port
sudo ovs-vsctl -- --id=@p get Port "$automud_sensor_port" \
  -- --id=@m create Mirror name=automud select-all=true output-port=@p \
  -- set Bridge s1 mirrors=@m
sudo ovs-vsctl list Mirror
```

The example port is not guaranteed. Configure mirrors idempotently and reserve
their output port for observation. [OVS mirroring documentation](https://docs.openvswitch.org/en/latest/faq/configuration/).

## 8. Finish the complete pipeline

Start qualified Ryu/OVS, then controller-managed Mininet/MUD base flows/mirror,
then Zeek/finalizer, then the supplied GNN service and MUD evaluation, then the timed orchestrator
join and Decision Engine in observation mode. Add event/explanation/dashboard
services, then verify a scoped action and recovery before enabling responses.
The integration READMEs are ownership descriptions, not runnable services.

If using FastAPI, qualify its dependencies in a separate application environment.
Neo4j is optional observation storage; the backend owner configures it if chosen.
Do not invent frontend launch commands before its actual package/build exists.

Configuration must supply absolute paths, inventory and UTC clock rules, sensor
interface, controller address/DPID, service routes/timeouts, history retention,
policy versions and action TTLs. Measure end-to-end timing separately from model
inference. Validate actual OpenFlow table entries/counters and traffic effect.

Common failures: missing model files after an old clone, Zeek absent from service
PATH, incorrect sensor namespace, stale identity, missing native clock, discarded
history, mismatched dependencies, Ryu import errors, or a rule targeting the wrong
DPID/port. Resolve the actual error; null scores must not become healthy decisions.

The full pipeline is complete only after live feature parity, evidence joins,
enforcement/expiry, outage/restart and swap/rollback tests pass. The fixture proves loading/output reproduction; supplied ML acceptance covers the ML branch. Evidence joins and action effect/expiry remain team checks.

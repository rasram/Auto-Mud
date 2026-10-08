# Mininet/OVS setup for database-free GNN collection

Current local setup and v2 dataset/model requirements: [LOCAL_WSL.md](LOCAL_WSL.md).
The local pipeline and monitoring command are documented there. Use fresh output directories.

This guide targets a **dedicated Ubuntu 24.04 VM or Linux host** with the Auto-MUD
repository on a native Linux filesystem. Run commands from the repository root
unless a command says otherwise. The current GNN collection path is:

`collection plan → Mininet hosts + Open vSwitch → mirrored tcpdump PCAP → Zeek
minute telemetry → graph snapshots → GraphSAGE`.

There is no Neo4j service, export step, or database connection in this path.
Ryu is also not in the current **collection** path: `network.testbed.collect`
creates an OVS bridge in standalone mode and captures traffic before any policy
enforcement. `network/sdn/` currently contains a roadmap README, not a working
Ryu response application. A separate Ryu connectivity check appears below so
controller setup does not contaminate the training captures.

## 1. Prepare the Linux machine

Use a VM with working Linux network namespaces and OVS kernel support. Allocate
several CPU cores, enough RAM for Mininet/Zeek and training, and enough disk for
raw PCAPs and derived logs. Size disk from a one-hour pilot using the procedure
below; keep about 25% extra space. Keep the long run on reliable storage. A
Windows-hosted WSL filesystem mount may work for development, but this collection
runner has not been validated for a multi-day run there. Do not run other Mininet
topologies on the same host while capturing.

```bash
sudo apt update
sudo apt install -y software-properties-common ca-certificates curl gnupg \
  python3 python3-venv python3-pip mininet openvswitch-switch \
  tcpdump ethtool wireshark-common
sudo systemctl enable --now openvswitch-switch
python3 -c 'import mininet; print("Mininet Python import OK")'
mn --version
ovs-vsctl --version
sudo ovs-vsctl show
tcpdump --version
ethtool --version
mergecap --version
```

If Ubuntu reports that `mininet` or `wireshark-common` is unavailable, enable
the Ubuntu `universe` repository (`sudo add-apt-repository universe`), update,
then retry. The Mininet and OVS package choices follow the
[Mininet installation guide](https://mininet.org/download/) and
[OVS Debian/Ubuntu packaging guide](https://docs.openvswitch.org/en/stable/intro/install/debian/).
The `wireshark-common` package supplies `mergecap` on Ubuntu.

Verify a fresh, disposable OVS/Mininet network **before** the Auto-MUD run:

```bash
sudo mn --switch ovsbr --test pingall
sudo mn -c
sudo ovs-vsctl br-exists s1; echo "s1 exit status: $?"
```

`pingall` should succeed. After cleanup, `br-exists s1` should return nonzero.
Only run `mn -c` when no experiment is active; it tears down Mininet state.
If OVS fails, inspect `systemctl status openvswitch-switch`, verify the Linux
kernel module is available, and retry the disposable test before collecting data.

## 2. Install Zeek and the project Python environment

Install Zeek using the [official Zeek Linux package instructions](https://docs.zeek.org/en/lts/install.html).
For Ubuntu **24.04**, the current LTS example is:

```bash
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
  sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
sudo apt update
sudo apt install -y zeek-8.0
export PATH="/opt/zeek/bin:$PATH"
zeek --version
```

Use the official page's repository path/package for another Ubuntu release.
Put `/opt/zeek/bin` on your shell's persistent `PATH` after verifying the
installation. The extractor runs Zeek **offline** on the completed PCAP; it does
not require a permanently running Zeek daemon.

Create the training/analysis environment as your normal user. Ubuntu 24.04's
default Python is 3.12, the version used by this module:

```bash
cd /path/to/Auto-Mud
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-ml.txt
python -m pytest ml/tests -q
python scripts/validate_gnn_sensor.py --out tmp/sensor-acceptance
```

The last command checks Zeek's interval counters against a known PCAP. Use
`sudo /usr/bin/python3` for the Mininet collector: the Ubuntu Mininet package is
installed for the system interpreter, and the collector itself does not import
PyTorch. Use the activated `.venv` Python for plan creation, Zeek extraction,
preparation, and training. Do not run the complete ML environment under `sudo`.

## 3. Calibrate traffic and run a one-hour pilot

Complete [COLLECTION.md step 2](COLLECTION.md#2-re-extract-public-normal-traffic-and-calibrate-the-generator)
first. It extracts/reviews the twelve UNSW normal PCAPs, creates reviewed
manifests, and writes `data/gnn/generator-profiles.json`. The older
`device_traffic_profiles.json` is not the schema accepted by this collector.

The supplied [topology](../../network/testbed/topology.json) defines twelve
devices at `10.0.0.11`–`10.0.0.22` and six intentional device-to-device
relationships. The collector adds local simulated cloud addresses
`10.0.0.100`–`10.0.0.115`, a sensor host, and an OVS mirror on `s1`. It does
not require Internet access for the simulated devices or configure NAT.

```bash
source .venv/bin/activate
python -m ml plan-normal --days 0.041666666666666664 --seed 101 \
  --profiles data/gnn/generator-profiles.json \
  --out data/collection/pilot-plan.json
sudo /usr/bin/python3 -m network.testbed.collect \
  --plan data/collection/pilot-plan.json --out data/collection/pilot
python -m ml extract --pcap data/collection/pilot/capture.pcap \
  --out data/collection/pilot/zeek
python -m ml inspect-capture \
  --manifest data/collection/pilot/manifest.json \
  --telemetry data/collection/pilot/zeek/telemetry.jsonl \
  --out data/gnn/pilot-quality.json
```

While the pilot is running, in another terminal you can check the OVS bridge
and mirror with `sudo ovs-vsctl show` and `sudo ovs-vsctl list Mirror`.
Afterwards, inspect `data/collection/pilot/manifest.json`, its `logs/` directory,
`data/gnn/pilot-quality.json`, the Zeek telemetry, and the PCAP. Require
`capture_complete=true`, `capture_drops=0`, successful agents/responders, and
visible bidirectional normal traffic. Compare observed feature quantiles with
the calibration captures. A failed/incomplete run is diagnostic data; create a
**new** run directory for a retry. The runner refuses to overwrite captures.
Estimate full-run storage from the pilot PCAP rate plus logs and working space.

For a quick infrastructure check before UNSW calibration, omit `--profiles`
and add `--smoke` to the collector. This is marked unsuitable for production
training. Never remove that provenance flag to make it pass a training gate.

## 4. Collect and train Heads A/B first

After the pilot passes, collect the seven-day normal run. The fixed default
split is four days to train, one to validate, one to calibrate thresholds, and
one untouched normal test day. Collection is **real-time** on Mininet.

```bash
python -m ml plan-normal --days 7 --seed 42 \
  --profiles data/gnn/generator-profiles.json \
  --out data/collection/normal-plan.json
sudo /usr/bin/python3 -m network.testbed.collect \
  --plan data/collection/normal-plan.json --out data/collection/normal
python -m ml extract --pcap data/collection/normal/capture.pcap \
  --out data/collection/normal/zeek
python -m ml inspect-capture \
  --manifest data/collection/normal/manifest.json \
  --telemetry data/collection/normal/zeek/telemetry.jsonl \
  --out data/gnn/normal-quality.json
python -m ml make-normal-config --normal-run data/collection/normal \
  --out data/gnn/normal-sources.json
python -m ml prepare --config data/gnn/normal-sources.json \
  --out data/gnn/normal-prepared
python -m ml readiness --stage1-only \
  --catalog data/gnn/normal-prepared/catalog.json
python -m ml train-stage1 \
  --catalog data/gnn/normal-prepared/catalog.json \
  --out data/gnn/models/ab-stage1.pt --epochs 100 --patience 10 --seed 42
python -m ml calibrate \
  --catalog data/gnn/normal-prepared/catalog.json \
  --checkpoint data/gnn/models/ab-stage1.pt \
  --out data/gnn/models/ab-calibrated.pt
python -m ml evaluate \
  --catalog data/gnn/normal-prepared/catalog.json \
  --checkpoint data/gnn/models/ab-calibrated.pt \
  --partition normal_test --out data/gnn/models/ab-normal-test.json
```

The stage-one quality gate checks held-out reconstruction and link performance;
passing it is a minimum engineering check, not proof of intrusion detection.
Inspect normal-test alert rate, per-type coverage, link candidate diversity,
and any calibration fallback. A normal-only test estimates false alarms, **not**
attack recall: use a small separately labeled attack pilot for development, then
leave independent attack sessions untouched for final evaluation. Compare
against simple non-graph baselines before claiming the GNN improves the main
use case. If the gate fails, improve collection or model behavior rather than
silently training Head C on weak embeddings.

## 5. Collect Head C sessions and train the full model

Head C uses the **frozen encoder learned in stage one**, so it cannot be trained
as an independent classifier on raw attack CSVs. Its positives must be verified
compromised **actors**, including `from_start` episodes; attacked victims are
not positives. The matched controls and held-out sessions are essential to
avoid learning scenario or capture artifacts. See
[COLLECTION.md step 5](COLLECTION.md#5-extra-head-c-data-labeled-attacks-and-matched-controls)
for the attack design and [step 6](COLLECTION.md#6-public-datasets-for-head-c)
for the limits of CIC/UNSW labels.

```bash
python -m ml plan-attacks --profiles data/gnn/generator-profiles.json \
  --out data/collection/scenario-plans
sudo /usr/bin/python3 scripts/collect_gnn_matrix.py \
  --matrix data/collection/scenario-plans/matrix.json \
  --runs-root data/collection/scenarios --zeek /opt/zeek/bin/zeek --limit 2
# Inspect the pilot pair; then rerun the same command without --limit.
python -m ml make-config --normal-run data/collection/normal \
  --matrix data/collection/scenario-plans/matrix.json \
  --runs-root data/collection/scenarios --out data/gnn/sources.json
python -m ml prepare --config data/gnn/sources.json --out data/gnn/prepared
python -m ml readiness --catalog data/gnn/prepared/catalog.json
python -m ml train-all --catalog data/gnn/prepared/catalog.json \
  --out data/gnn/models/sage --epochs 100 --patience 10 --seed 42
```

`train-all` retrains stage one against the **final catalog** before fitting
Head C. This is required because checkpoints are bound to their prepared
catalog hash. The earlier A/B run remains useful for finding data and model
problems before spending time on the attack matrix. Full real-time collection
is seven days normal plus 240 twenty-minute scenario/control runs (80 hours),
excluding startup, extraction, and retries. The separate
[virtual-clock option](COLLECTION.md#real-mininet-time-and-fast-virtual-packet-time)
can shorten software iteration but remains synthetic.

## 6. Ryu: separate controller check, not GNN collection

The project plans Ryu/OVS response enforcement later, but the checked-in
`network/sdn/` directory has no runnable Auto-MUD controller. Do not start Ryu
for the commands above: they explicitly use `controller=None`, `OVSBridge`, and
`failMode=standalone`. The decision engine and OpenFlow rule translation must be
implemented and tested before claiming alert/rate-limit/quarantine/block works.

If you want to check **Ryu ↔ OVS connectivity** independently, use a separate
Python environment where Ryu actually installs and starts. Ryu's upstream
[repository](https://github.com/faucetsdn/ryu) states it is unmaintained;
its Python 3.12 compatibility is not assured. Do not put it in the GNN venv.
To attempt the upstream package in an isolated environment:

```bash
python3 -m venv ~/ryu-venv
~/ryu-venv/bin/python -m pip install --upgrade pip
~/ryu-venv/bin/python -m pip install ryu
~/ryu-venv/bin/ryu-manager --help
```

If installation or startup fails on your Python version, stop here and use a
Ryu-compatible interpreter/VM later; this does not block GNN collection. Once
the check succeeds, run in terminal A:

```bash
~/ryu-venv/bin/ryu-manager --ofp-tcp-listen-port 6653 ryu.app.simple_switch_13
```

Then run a **disposable** two-host network in terminal B:

```bash
sudo mn --topo single,2 --switch ovsk,protocols=OpenFlow13 \
  --controller remote,ip=127.0.0.1,port=6653 --test pingall
sudo mn -c
```

The Ryu log should show a switch connection and `pingall` should succeed.
This does **not** attach Ryu to `network.testbed.collect`, test response tiers,
or produce a GNN training capture. OVS needs OpenFlow 1.3 enabled for that
sample app; the [OVS OpenFlow guide](https://docs.openvswitch.org/en/stable/faq/openflow/)
documents version selection. A later controller-enabled testbed mode should
have its own capture/manifest provenance and be validated separately.

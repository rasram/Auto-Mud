# Collecting the data and preparing training inputs

Current local setup and v2 dataset/model requirements: [LOCAL_WSL.md](LOCAL_WSL.md).
The local pipeline and monitoring command are documented there. Use fresh output directories.

Commands below run from the repository root. Linux paths are examples: your Windows
dataset paths are available in WSL under `/mnt/e/Projects_Archive/FYP/...`.

## 1. Prepare the environments

Use Python 3.12 and `requirements-ml.txt` for training. No Neo4j/Ryu installation is
needed for this module. On the Linux collection machine install Mininet, Open
vSwitch, tcpdump, ethtool, and mergecap (the Wireshark CLI package), and install Zeek
using its supported distribution instructions. Verify:

```bash
python3 -c 'import mininet'
ovs-vsctl --version
tcpdump --version
zeek --version
mergecap --version
```

Mininet collection needs root and working OVS/kernel network namespaces. Use a
dedicated test VM or host. The new runner supplies local simulated cloud services
and does not configure NAT. It refuses to overwrite a capture directory or reuse an
existing `s1` bridge. Run one household at a time on a host.

### Real Mininet time and fast virtual packet time

The runner opens real TCP/UDP sockets; tcpdump and Zeek timestamp the packets using
the host clock. A 60-second graph is one actual minute of observed traffic. Running
seven virtual days through the legacy accelerated replay in a few minutes would
make flow rates, timeout outcomes, daily cycles, and minute windows represent a
different process. Merely changing a `replay_speed` field would not fix that.
Separate virtual packet generation is now available. It renders the same collection
plans directly to a PCAP with a seven-day UTC timeline. Generation and offline Zeek
analysis run as fast as the computer allows; the PCAP timestamps still span seven
days, so the extractor and graph builder retain the ordinary 60-second windows,
time-of-day features, and Head C onset labels. The manifest records
`source=virtual_testbed`, `clock_mode=virtual_packet_time`, and `synthetic=true`.
`replay_speed=1` describes the **packet timestamp timeline**, not the wall-clock
rendering speed. The virtual run does not execute the Mininet hosts, OVS, Linux
TCP/socket stack, congestion, losses, or application protocols. Its traffic is a
discrete simulation based on the plan and calibrated profiles. Model training is
supported on these captures, but measured real-capture validation is required
before claiming performance on live devices.

For the fast path, first complete the UNSW-normal extraction and profile
calibration in step 2. Run the following from a Linux/WSL environment with Python,
Scapy, and Zeek installed. `1704067200` is 2024-01-01 00:00 UTC. The scenario
matrix spreads sessions across different times of day while keeping each
attack/control pair at the same time; the renderer rebuilds the calibrated
schedule for that UTC phase and records the executed plan hash.
All paths below are separate from the real Mininet run directories.

```bash
python -m ml plan-normal --days 7 --seed 42 \
  --profiles data/gnn/generator-profiles.json \
  --out data/collection/virtual-normal-plan.json
python -m network.testbed.virtual_capture \
  --plan data/collection/virtual-normal-plan.json \
  --out data/collection/virtual-normal --start 1704067200
python -m ml extract --pcap data/collection/virtual-normal/capture.pcap \
  --out data/collection/virtual-normal/zeek
python -m ml plan-attacks --profiles data/gnn/generator-profiles.json \
  --out data/collection/virtual-scenario-plans
python scripts/collect_gnn_matrix.py --virtual --start 1704067200 \
  --matrix data/collection/virtual-scenario-plans/matrix.json \
  --runs-root data/collection/virtual-scenarios
python -m ml make-config --normal-run data/collection/virtual-normal \
  --matrix data/collection/virtual-scenario-plans/matrix.json \
  --runs-root data/collection/virtual-scenarios \
  --out data/gnn/virtual-sources.json
python -m ml prepare --config data/gnn/virtual-sources.json \
  --out data/gnn/virtual-prepared
python -m ml readiness --catalog data/gnn/virtual-prepared/catalog.json
python -m ml train-all --catalog data/gnn/virtual-prepared/catalog.json \
  --out data/gnn/models/virtual-sage --epochs 100 --patience 10 --seed 42
```

Pilot first: use `--days 0.041666666666666664` and `--smoke` on the virtual
capture command for a one-hour software check. Smoke data cannot pass production
readiness. The complete seven-day run is still required by `make-config`.
Rendering time depends on calibrated event rate, disk speed, and Zeek throughput;
it is no longer tied to seven calendar days. Compare virtual and real pilot feature
quantiles using `ml inspect-capture`, then test any trained model on held-out real
captures. Keep the real and virtual test results separate.

For the real Mininet workflow, allow at least **7 days + 80 hours = 10
days 8 hours** of wall time, plus pilot, startup, extraction, and QC. The seven
days are the chosen coverage target (four train, one validation, one calibration,
one untouched test), not a mathematical minimum. The current `make-config`
helper explicitly requires seven days. A shorter exploratory study needs its own
declared chronological split configuration and enough active observations; it
cannot be represented as a completed default collection. `python -m ml smoke`
tests the software immediately using synthetic data, without claiming detection
performance.

## 2. Re-extract public normal traffic and calibrate the generator

The supplied UNSW normal directory contains all twelve topology device captures:

| Device | PCAP filename |
|---|---|
| SmartThings | `SamsungSmartThings_d052a800675e.pcap` |
| Echo | `AmazonEcho_44650d56ccd3.pcap` |
| Hue | `PhilipsHue_0017882b9a25.pcap` |
| WeMo switch | `BelkinWemoSwitch_ec1a5979f489.pcap` |
| Samsung camera | `SamsungCamera_00166cab6b88.pcap` |
| DropCam | `NestDropCam_308cfb2fe4b2.pcap` |
| Doorbell | `AugustDoorBell_e076d03f00ae.pcap` |
| Motion sensor | `BelkinWemoMotionSensor_ec1a59832811.pcap` |
| Printer | `HPPrinter_705a0fe49bc0.pcap` |
| Weather station | `NetatmoWeatherStation_70ee5003b8ac.pcap` |
| Air-quality sensor | `AwairAirQuality_70886b100fc6.pcap` |
| Scale | `WithingsSmartScale_0024e41b6f96.pcap` |

Process each capture separately. Some `.pcap` files actually contain PCAPNG; Zeek
recognizes the file format. Do not pool per-device captures into a fictional graph.

```bash
python -m ml extract \
  --pcap /mnt/e/Projects_Archive/FYP/UNSW-IoTraffic/UNSW-IoTraffic/pcaps/AmazonEcho_44650d56ccd3.pcap \
  --out data/gnn/public/echo/zeek
```

`configs/gnn/unsw-identities.json` maps the twelve MAC addresses to canonical IDs and
functional types. Create and review a manifest:

```bash
python -m ml public-manifest \
  --telemetry data/gnn/public/echo/zeek/telemetry.jsonl \
  --identities configs/gnn/unsw-identities.json \
  --source unsw_normal --run-id unsw-echo --normal \
  --out data/gnn/public/echo/manifest.json
```

The helper derives observed address intervals and conservative study bounds. It
leaves `capture_complete=false`: inspect capture continuity, missing chunks,
Zeek warnings, and IP ownership before setting it true. A months-long file may
contain observation gaps; record those in `outages` instead of treating them as
months of known idle activity. The identities file is for the twelve UNSW devices,
not for CIC devices with unrelated addresses.

Create a calibration source file listing all twelve reviewed manifests/telemetry
files; paths resolve relative to that file:

```json
{"sources":[
  {"manifest":"public/echo/manifest.json",
   "telemetry":"public/echo/zeek/telemetry.jsonl",
   "device_ids":["AmazonEcho_44650d56ccd3_flows"]}
]}
```

Save it as `data/gnn/calibration-sources.json`, extend with the other devices, then:

Select only the file's target device using `device_ids`; its capture may also
contain partial observations of another household device. Use canonical IDs from
`unsw-identities.json`, exactly one calibration source per target device. Only
reviewed complete capture intervals outside declared outages contribute profiles.

```bash
python -m ml calibrate-traffic \
  --sources data/gnn/calibration-sources.json \
  --out data/gnn/generator-profiles.json
```

This generates **new** `automud.generator.v1` profiles. The legacy
`device_traffic_profiles.json` is not schema-compatible. Calibration derives
inter-flow scheduling gaps from connection starts, uses seconds throughout, and
keeps TCP/UDP transport and service port coupled. The profile records its simulation
approximations and limits; inspect these against intended behavior before collecting
seven days. Keep public normal capture intervals used for calibration out of any
claimed independent public test set.

## 3. Pilot before the long run

```bash
python -m ml plan-normal --days 0.041666666666666664 --seed 101 \
  --profiles data/gnn/generator-profiles.json \
  --out data/collection/pilot-plan.json
sudo python3 -m network.testbed.collect \
  --plan data/collection/pilot-plan.json --out data/collection/pilot
python -m ml extract --pcap data/collection/pilot/capture.pcap \
  --out data/collection/pilot/zeek
```

`python3` used with sudo must be the Linux interpreter able to import Mininet.
The collection code itself does not import torch. If Mininet is installed through
the distribution, normally use `/usr/bin/python3`; use the training venv for ML.

Check the manifest and per-agent summaries: zero unexpected failures, zero events
late by more than one second, zero capture drops, and complete capture. Inspect the
Zeek logs: normal TCP must establish, response bytes must be present, and planned
household edges must occur. Compare observed volume/timing/port distributions with
calibration profiles. Exact packet counts are not guaranteed by TCP socket writes;
the captured traffic, not intent logs, is the training source.

Generate a numerical pilot report (and optionally compare it with a reference
report produced from a reviewed UNSW manifest):

```bash
python -m ml inspect-capture --manifest data/collection/pilot/manifest.json \
  --telemetry data/collection/pilot/zeek/telemetry.jsonl \
  --out data/gnn/pilot-quality.json
# Add --reference path/to/unsw-quality.json for side-by-side feature quantiles.
```

For a quick infrastructure test without calibration, omit `--profiles`, generate
a short plan, and pass `--smoke` to collection. This marks the dataset as unsuitable
for production training. Do not relabel that dataset as measured UNSW-like traffic.

## 4. Seven days of clean data for Heads A/B

```bash
python -m ml plan-normal --days 7 --seed 42 \
  --profiles data/gnn/generator-profiles.json \
  --out data/collection/normal-plan.json
sudo python3 -m network.testbed.collect \
  --plan data/collection/normal-plan.json --out data/collection/normal
python -m ml extract --pcap data/collection/normal/capture.pcap \
  --out data/collection/normal/zeek
```

Seven days produce 10,080 minute graphs and 120,960 device-windows at twelve devices:
four days train, one validation, one threshold calibration, one untouched normal
test. Activity, not row count alone, determines useful coverage. Extend collection
if a type is mostly idle or a normal edge rarely occurs. Per-type threshold tails
require at least 500 eligible observations; otherwise the code records a pooled
fallback. A 99th-percentile threshold based on few observations is uncertain.

Do not scale seven days of packet timestamps into seconds or count repeated
identical replay files as independent days. The virtual mode above instead
simulates the full seven-day timestamp range. Include idle periods and legitimate high-volume/user-triggered
activity. The model does not become empirically validated merely by meeting a quota.

Estimate storage using the pilot: `pilot PCAP bytes / pilot seconds × collection
seconds`, plus derived logs and approximately 25% working headroom. High-volume
attack captures may need a separate estimate. Preserve manifests, plans, seeds,
labels, checksums, agent summaries, and sensor logs alongside captures.

## 5. Extra Head C data: labeled attacks and matched controls

```bash
python -m ml plan-attacks --profiles data/gnn/generator-profiles.json \
  --out data/collection/scenario-plans
```

The resulting `matrix.json` lists 240 plans:

- Four behaviors: port scan, lateral connections, exfiltration-like transfer, and
  periodic beaconing.
- Three actors: Samsung camera, SmartThings hub, WeMo plug.
- Five independent seeds; seeds 1–3 train, 4 validate, 5 test.
- Two onset modes: first observed event is malicious, or five clean minutes first.
- Attack plus matched normal control; twenty minutes per run.

Sequential duration is 80 hours plus startup/drain overhead. Attack runs yield
approximately 2,100 positive actor-windows before quality exclusions, plus normal
peers and matched controls. This is an initial controlled experiment, not a proven
minimum for generalization. Expand actors/seeds/behavior diversity if held-out
results or learning curves show inadequate coverage.

Use `scripts/collect_gnn_matrix.py` to run and extract the complete matrix, or a
small subset first:

```bash
sudo python3 scripts/collect_gnn_matrix.py \
  --matrix data/collection/scenario-plans/matrix.json \
  --runs-root data/collection/scenarios --zeek /opt/zeek/bin/zeek --limit 2
# After validating the pilot, omit --limit; completed matching runs can be resumed.
```

The runner writes actor/time labels automatically. Default Mininet capture is real-time; failures
make the manifest incomplete. Attack/control pairs share a session ID and never
cross training/test partitions. These scenarios use controlled endpoints and
bounded traffic, not real malware. Exfiltration/beaconing behavior can overlap with
legitimate uploads/polling; matched controls make that limitation measurable.

## 6. Public datasets for Head C

**CIC normal:** use `BenignTraffic.pcap`, `BenignTraffic1.pcap`,
`BenignTraffic2.pcap`, `BenignTraffic3.pcap` under your CIC root.

**CIC attack candidates:** `Recon-PortScan.pcap`, `Recon-OSScan.pcap`, and
`Backdoor_Malware.pcap`. The two `MITM-ArpSpoofing*.pcap` files require an ARP-aware
schema extension for direct ARP detection; they are not supported positive examples
for the initial IP-only model merely because their filenames say attack.

Re-extract PCAPs with the canonical policy. Existing CIC `zeek-out` logs are useful
for inspection but lack the canonical interval rows and MAC logging. Split PCAP
parts from the same original capture must be extracted together (`--pcap part1
part2 ...`, using mergecap) and kept in the same supervised partition.

Obtain the original experiment's actor MAC/IP mapping and attack intervals from
verified supplementary metadata or a reviewed capture analysis. Do not guess actor
identity from the busiest IP. A capture named Backdoor may also contain normal
devices and victims. Prepare an identity file and `labels.jsonl` in the v1 contracts.
Unverified actors/intervals remain excluded. CIC's 309 per-capture feature CSVs and
63 merged CSVs cannot recover identity, time windows, direction, or topology.

**UNSW attack:** the local `attack+benign-pcaps/` directory now contains all 17
daily attack/benign PCAPs offered by the [UNSW release](https://iotanalytics.unsw.edu.au/attack-data.html)
(June 1–8 and 20; October 20–27, 2018). Some `.pcap` files contain PCAPNG. The
local `attackinfo.xlsx` workbook identifies ten IoT targets, their MAC/IP mappings,
experiment types, and attacker IPs. Its attacker IPs (`192.168.1.205`,
`192.168.1.229`, `149.171.36.239`) are outside the ten listed device IPs.
`annotations/annotations/*.csv` gives impacted device intervals. These are
**attacks against devices**, not proof that those IoT devices became compromised;
do not turn the target annotations into positive Head C labels.

Refresh the machine-readable audit and generate an identity template from the
workbook:

```bash
python -m ml audit-datasets \
  --cic /mnt/e/Projects_Archive/FYP/CICIOT2023 \
  --unsw-normal /mnt/e/Projects_Archive/FYP/UNSW-IoTraffic/UNSW-IoTraffic \
  --unsw-attack /mnt/e/Projects_Archive/FYP/UNSW-IoTraffic/UNSW-IoT-Attack \
  --out data/gnn/public-inventory.json
python -m ml unsw-attack-identities \
  --workbook /mnt/e/Projects_Archive/FYP/UNSW-IoTraffic/UNSW-IoT-Attack/attackinfo.xlsx \
  --out data/gnn/unsw-attack-identities.json
python -m ml extract \
  --pcap /mnt/e/Projects_Archive/FYP/UNSW-IoTraffic/UNSW-IoT-Attack/attack+benign-pcaps/18-06-01.pcap \
  --out data/gnn/public/unsw-18-06-01/zeek
```

Review the generated identities and each capture before `public-manifest` and
labelling. The audit records each file's **first packet UTC timestamp**; October
files start near 13:00 UTC on the preceding calendar date. Select an annotation's
PCAP by its packet timestamps, not just the filename. Extract separate days as
separate runs unless verified packet continuity calls for merging adjacent parts.
For example, after reviewing the first extracted day's identities, generate its
review manifest:

```bash
python -m ml public-manifest \
  --telemetry data/gnn/public/unsw-18-06-01/zeek/telemetry.jsonl \
  --identities data/gnn/unsw-attack-identities.json \
  --source unsw_attack --run-id unsw-18-06-01 \
  --out data/gnn/public/unsw-18-06-01/manifest.json
```

It remains `capture_complete=false` until capture and lease QC. Do not add
`--normal` merely because a day contains benign periods.
Three TP-Link annotation rows have extra columns and remain quarantined in the
audit. The ten MUD flow-counter CSVs cannot replace canonical interval extraction.

The UNSW traces are useful for testing whether Heads A/B or C mistake *attacked
victims* for compromised actors. Any true positive Head C episode needs separate
evidence that a listed device actually acted maliciously, along with its interval.
Until then, Head C positive training comes from the labelled Mininet scenarios.

**CIC actor evidence:** the newly supplied `README_Victims_List.pdf` identifies
targets only. The shared Google AI summary likewise says the processed CSVs lack
actor identities and time intervals. Neither is actor ground truth. Keep CIC attack
nodes unlabelled for Head C until actor/compromise role and interval are verified.

If verified public actor examples are later added to Head C, include source-matched
verified benign examples. Training on CIC attacks versus UNSW normal data alone
would let the classifier learn dataset identity. Keep public results separate from
Mininet results, and reserve independent sessions for validation/test. The model
can be trained first on the complete Mininet matrix; missing public actor metadata
does not justify fabricating labels.

## 7. Prepare the final training catalog

```bash
python -m ml make-config --normal-run data/collection/normal \
  --matrix data/collection/scenario-plans/matrix.json \
  --runs-root data/collection/scenarios --out data/gnn/sources.json
python -m ml prepare --config data/gnn/sources.json --out data/gnn/prepared
python -m ml readiness --catalog data/gnn/prepared/catalog.json \
  --out data/gnn/readiness.json
```

Add verified public sources to `sources.json` **before training**. Each entry names
manifest, telemetry, labels, and explicit partition/time bounds. Both stages and
evaluation use the same catalog hash. A completed flow-summary CSV is not a
substitute for interval telemetry. Changing schemas/scalers or partitions requires
new preparation and training, not loading incompatible checkpoints.

The public *attack* subsection is optional for the first Mininet-trained Head C:
the available CIC/UNSW victim information does not supply compromised-device
positives. The UNSW **normal** PCAP preparation in step 2 is required to calibrate
the default traffic generator. After the full normal run and all 240 scenario runs
are captured and extracted, `make-config` and `prepare` must finish and
`python -m ml readiness --catalog data/gnn/prepared/catalog.json` must return
`ready: true`. Only then run `python -m ml train-all --catalog
data/gnn/prepared/catalog.json --out data/gnn/models/sage --epochs 100 --patience
10 --seed 42` from the environment with `requirements-ml.txt` installed.
Training can still stop at the held-out Stage-1 quality gate; inspect its report
and improve the data/model rather than treating a failed diagnostic checkpoint as
trained output.

# GraphSAGE implementation and training runbook

This is the implementation guide for AutoMUD's database-free three-head GNN.
The software is trainable once validated captures and actor labels are available.
The included synthetic smoke run is a software test, not a pretrained detector.

Read these in order:

1. [Data contracts and feature definitions](SCHEMA.md)
2. [Linux Mininet/OVS setup without Neo4j](TESTBED_SETUP.md)
3. [Collection, dataset selection, and exact commands](COLLECTION.md)
4. [Existing generator audit and changes](TRAFFIC_GENERATION.md)
5. [Training, evaluation, and integration](TRAINING.md)
6. [Machine-generated inventory of the supplied datasets](dataset-inventory.json)
7. [Validation performed and remaining integration checks](VALIDATION.md)

## What has been implemented

`ml/` provides versioned schemas, telemetry validation, causal graph construction,
explicit chronological/session splits, per-type normalization, two-layer mean
GraphSAGE, reconstruction and link heads, a classifier on frozen embeddings,
calibration, inference, metrics, and GCN/node-only ablations. Nothing imports Neo4j.

`network/zeek/automud-window.zeek` produces the canonical minute-level telemetry.
The same policy processes testbed captures and public PCAPs. A connection that spans
several minutes contributes only that minute's packet/IP-byte counts to each graph.

`network/testbed/collection_plan.py`, `socket_traffic.py`, and `collect.py` provide
deterministic plans, working bidirectional TCP/UDP exchanges, an isolated Mininet
runner, dedicated OVS capture, and automatically labeled attack/control sessions.
No payload exploits or actual malware are required: the scenarios simulate the
observable network behaviors described in the project objectives.

## Quick software verification

From the repository root, using Python 3.12:

```bash
python -m venv .venv
# Linux:
source .venv/bin/activate
# Windows PowerShell instead: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-ml.txt
python -m pytest ml/tests profiling/features profiling/profile_engine -q
python -m ml smoke --out tmp/gnn-smoke --epochs 3
# Linux with Zeek available:
python scripts/validate_gnn_sensor.py --out tmp/sensor-acceptance
```

The smoke command creates synthetic telemetry, trains both stages, calibrates the
signals, saves/reloads checkpoints, and writes an evaluation report. Every smoke
checkpoint and prediction is marked as such. Production training rejects smoke
catalogs. These metrics must not be quoted as measured intrusion-detection results.

## What you still need to supply

- A Linux host/VM with Mininet, Open vSwitch, tcpdump, ethtool, Zeek, and sufficient
  storage. Windows can train the model, but the collection runner requires Linux.
- Reviewed device identities and complete normal public captures to calibrate the
  revised generator; the existing calibration JSON is not accepted as v1 profiles.
- A pilot proving successful bidirectional traffic and clean capture, followed by
  seven distinct days of normal traffic for Heads A/B.
- The labeled Head C scenario matrix: separate normal controls, attacks starting at
  first observation, and attacks starting after a clean interval.
- Verified actor metadata for any public attacks added to Head C. Your current UNSW
  attack directory now includes the raw packet captures and `attackinfo.xlsx`, but
  its victim annotations are insufficient as compromised-actor labels.

The capture and dataset readiness gates deliberately stop on missing information.
They do not synthesize graph context, infer attacker identities from high volume,
or substitute zero for a missing public feature.

## Pipeline responsibilities

The generator establishes intended traffic and ground truth. OVS/tcpdump/Zeek
establish what was actually observed. The inventory establishes identity and type.
The ML extractor establishes numeric windows and observed relationships. The
profiling engine learns its separate policy/deviation signal from the same traffic.

The model produces three independent signals. The downstream Decision Engine owns
fusion with the profiling score and any Ryu/OVS response. This implementation does
not change MUD allowlists, deploy blocking rules, or silently learn a new baseline
from live anomalies.

Head C needs no clean baseline for the device being scored. Its learned evidence
comes from other labeled examples. It detects observable known-pattern behavior;
neither its probability nor any other head proves that an otherwise normal-looking
device contains malware.

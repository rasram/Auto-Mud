# AutoMUD (AutoShield)

**Behavioral Profiling and Supervised Detection for Adaptive Microsegmentation in Smart Home IoT Security**

Team A12, Amrita School of Artificial Intelligence, Coimbatore. Supervisor: Mr. Vipin Das.

> AutoMUD combines traffic-based detection with independent MUD permission evidence and SDN response. The supervised E1+Q evidence service is supplied; full policy, controller and response integration remains team work.

For current implemented GNN behavior and pipeline ownership, use the shared setup/API/handoff guides below. Earlier methodology descriptions are background proposals and do not establish implementation or measured performance.

For the current **supervised E1+Q teammate package**, use
[the selected model guide](docs/gnn/README.md),
[Linux setup](docs/gnn/LINUX_PIPELINE_SETUP_20261012.md), and
[pipeline handoff](docs/gnn/LIVE_PIPELINE_HANDOFF_20261012.md).
The supervised joint E1 checkpoint, its frozen profile/normalizer/cutoffs, results and
a small loading/output fixture are shareable; full research datasets and old
development artifacts are private. The current E1+Q detector emits separate supervised A/B logits,
not a [0,1] compromise probability. The stateful GNN HTTP service is supplied; sensor finalization, MUD/Decision Engine/Ryu integration and full-pipeline acceptance remain teammate work.
E1 uses directed learned neighbor messages, graph-derived context and own-device history.
Earlier architecture/training descriptions below are project background.

---

## Objectives

1. **Automatic Profile Generation.** Generate per-device behavioral profiles from passive traffic metadata and compare them with MUDgee ground-truth MUD profiles (UNSW dataset).
2. **Live Relationship Graph.** Build a device communication graph in Neo4j and update it every 60 seconds so it reflects real-time topology changes.
3. **Anomaly Detection Performance.** Detect four attack classes (port scan, lateral movement, data exfiltration, C2 beaconing) with a high detection rate and a low false positive rate.
4. **Automated Response Latency.** Isolate a device through Open vSwitch within seconds of anomaly onset, measured from the first malicious packet to enforcement.
5. **Baseline Improvement.** Detect measurably better than the flow-only baseline of Wang et al. (2023), and reduce attack surface by more than the 65.85% of Osman et al. (2020).

## Architecture

| Stage | What happens | Where in repo |
|---|---|---|
| **0. Offline Foundation** | Zeek metadata supports the separate MUD/profile engine. Supervised C's frozen joint A/B checkpoint, clean profiles, normalizer and cutoffs are supplied in `models/gnn/`; research datasets are private. | `network/zeek/`, `profiling/`, `ml/`, `models/gnn/` |
| **1. Live Testbed** | Mininet + Open vSwitch virtual home network (8–10 device types), per-device traffic generators, OVS traffic mirrored to Zeek. | `network/testbed/`, `network/zeek/`, `profiling/traffic_gen/` |
| **2. Live Detection Loop** | Completed 60s telemetry feeds the MUD engine and ML-owned graph/history construction; frozen GNN emits separate behavioral A and relationship B scores/flags. Neo4j is optional observation storage. The GNN service is supplied; full pipeline integration remains to be built. | `integration/orchestrator/`, `profiling/profile_engine/`, `ml/`, `models/gnn/` |
| **3. Decision & Response** | Threshold Decision Engine picks a tier (alert / rate-limit / VLAN isolate / full block) → Ryu pushes OpenFlow rules to OVS; LLM module writes a plain-English alert; both go to the web dashboard. | `integration/decision_engine/`, `network/sdn/`, `integration/explanation/`, `dashboard/` |
| **4. Evaluation** | Four attack scenarios injected; compared against Suricata, a flow-only ablation, and a Wang 2023 replication; poisoned-baseline stress test. | `network/attacks/`, `integration/evaluation/` |

**Frozen deployment:** C's supervised training used earlier native-derived household traffic and authored attack overlays. The live service freezes its weights, clean profiles, normalizer and cutoffs; it never trains or refits on deployment traffic. Earlier methodology proposals are background, not the current learning-regime contract.

## Team & Ownership

| Member | Role | Owns |
|---|---|---|
| Anand Mahadev | Network Infrastructure Engineering | `network/` |
| Sarveshwar Balu | Data & Profiling Engineering | `profiling/` |
| Jayan Subramanian | ML Engineering | `ml/` |
| Rashwanth Ram | System Integration & Evaluation | `integration/`, `dashboard/` |
| All | Shared | `docs/`, `data/`, `configs/`, `scripts/`, `common/` |

## Repository Layout

```
network/          Mininet/OVS testbed, Zeek sensor, attack simulation, Ryu SDN enforcement
  testbed/  zeek/  attacks/  sdn/
profiling/        Feature extraction, traffic generators, profile engine, ground-truth validation
  features/  traffic_gen/  profile_engine/  validation/
ml/               Selected frozen inference, graph construction and telemetry/tensor utilities
  graph/  dataset_prep/  model/  ab_targets/  live/
models/gnn/       Supervised joint E1+Q checkpoint, frozen assets, manifest and results
fixtures/gnn/     Small consumed model-loading/output reproduction test
integration/      Live-loop orchestration, decision engine, LLM explanations, evaluation framework
  orchestrator/  decision_engine/  explanation/  evaluation/
dashboard/        Web dashboard
  backend/ (FastAPI)  frontend/ (React)
data/             Original datasets, reproducible derived data, and frozen artifacts
  raw/  processed/ (including testbed traffic/runs)  artifacts/
configs/          Shared configuration
scripts/          Cross-cutting helper scripts
common/           Shared Python utilities
docs/             Project documentation (canonical context doc)
```

Every directory has a `README.md` that describes what goes there and who owns it.

## Scope

**In scope:** metadata-based behavioral profiling (no DPI), automated SDN microsegmentation, GNN-based graph anomaly detection, simulation testbed validation, and a real-household prototype in Phase II.

**Out of scope:** DPI of encrypted payloads, federated learning, production router firmware, custom GNN architectures, and reinforcement learning policy agents.

## Status

The initial Mininet topology and calibrated traffic-generation workflow are in
place. Other modules will be built incrementally, and dependency versions in
`requirements.txt` will be pinned as each module is implemented.

The Zeek behavioral profiling pipeline is the maintained implementation. Its
selection and evaluation limits are documented in
[profiling/ENGINE_COMPARISON.md](profiling/ENGINE_COMPARISON.md).

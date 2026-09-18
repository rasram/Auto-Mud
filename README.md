# AutoMUD (AutoShield)

**Self-Supervised Behavioral Profiling and Graph Neural Network–Driven Adaptive Microsegmentation for Smart Home IoT Security**

Team A12, Amrita School of Artificial Intelligence, Coimbatore. Supervisor: Mr. Vipin Das.

> A system that silently watches every device on a home network, automatically learns what "normal" looks like for each device, builds a live map of how devices relate to each other, and automatically isolates any device that starts behaving suspiciously — with no human writing rules or profiles.

For the full motivation, literature review, research gaps, methodology, tool rationale, and timeline, see **[`docs/AutoMUD_Project_Context.md`](docs/AutoMUD_Project_Context.md)**. It is the source of truth for scope and architecture.

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
| **0. Offline Foundation** | UNSW PCAPs replayed through Zeek → per-device features → robust-statistics profile engine produces frozen MUD-like JSON profiles → compared against MUDgee ground truth. GraphSAGE trained on UNSW + N-BaIoT + CICIoT2023 graph snapshots, weights frozen. | `network/zeek/`, `profiling/`, `ml/`, `data/` |
| **1. Live Testbed** | Mininet + Open vSwitch virtual home network (8–10 device types), per-device traffic generators, OVS traffic mirrored to Zeek. | `network/testbed/`, `network/zeek/`, `profiling/traffic_gen/` |
| **2. Live Detection Loop** | Every 60s: frozen profile engine → deviation scores; Neo4j graph update; frozen GraphSAGE → per-device anomaly score [0.0–1.0]. | `integration/orchestrator/`, `profiling/profile_engine/`, `ml/graph/`, `ml/model/` |
| **3. Decision & Response** | Threshold Decision Engine picks a tier (alert / rate-limit / VLAN isolate / full block) → Ryu pushes OpenFlow rules to OVS; LLM module writes a plain-English alert; both go to the web dashboard. | `integration/decision_engine/`, `network/sdn/`, `integration/explanation/`, `dashboard/` |
| **4. Evaluation** | Four attack scenarios injected; compared against Suricata, a flow-only ablation, and a Wang 2023 replication; poisoned-baseline stress test. | `network/attacks/`, `integration/evaluation/` |

**Non-circularity:** The profile engine and GNN are trained offline on real datasets in Stage 0. Inside Mininet they run only in frozen inference mode and never relearn from simulated traffic. See §7 of the context doc.

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
ml/               Graph construction, dataset prep, GraphSAGE model, training
  graph/  dataset_prep/  model/  training/
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

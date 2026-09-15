# AutoMUD: Self-Supervised Behavioral Profiling and Graph Neural Network–Driven Adaptive Microsegmentation for Smart Home IoT Security

**Team A12 — Amrita School of Artificial Intelligence, Coimbatore**
Anand Mahadev (CB.SC.U4AIE23061) · Rashwanth Ram (CB.SC.U4AIE23045) · Sarveshwar Balu (CB.SC.U4AIE23063) · Jayan Subramanian (CB.SC.U4AIE23033)
**Supervisor:** Mr. Vipin Das

---

## 1. One-Line Summary

A system that silently watches every device on a home network, automatically learns what "normal" looks like for each device, builds a live map of how devices relate to each other, and automatically isolates any device that starts behaving suspiciously — with no human writing rules or profiles.

---

## 2. Domain Background & Motivation

- Average smart home in 2025 has ~20 IoT devices from different manufacturers — cameras, bulbs, plugs, TVs, doorbells (Source: NETGEAR & Bitdefender, 2025 telemetry, 6.1M households)
- Each device is a potential entry point: weak default credentials, infrequent firmware updates, no on-device security stack
- A compromised camera becomes a silent botnet node — attacking banks, hospitals, infrastructure — without the homeowner ever knowing

**Why this matters now:**
- Bitdefender recorded ~30 attack attempts per connected home per day in 2025
- Post-COVID WFH has merged home and corporate networks — a compromised home device can pivot into enterprise systems
- Mirai (2016) and Aisuru (2025) botnets both recruited compromised home IoT devices into DDoS attacks exceeding 15 Tbps
- IETF published RFC 8520 (MUD standard) in 2019, formally acknowledging the need for device behavioral policies — adoption is near zero because profiles must be manually authored

**Core gap:** Existing solutions require either manual rule authoring or human-written device profiles. No consumer product today automatically learns device behavior, detects anomalies in device *relationships*, and enforces isolation — without a human in the loop.

---

## 3. Literature Review

### Theme A — IoT Behavioral Profiling
| Paper | Method | Dataset | Result | Limitation |
|---|---|---|---|---|
| Hamza et al., ACM SIGCOMM IoT S&P, 2018 (MUDgee) | Automatically derives MUD profiles from device traffic traces | UNSW dataset | Generated accurate profiles capturing device communication patterns | Profiles are static artifacts — still require human deployment and maintenance |
| De Keersmaeker et al., IFIP Networking, 2024 | Richer interaction-aware MUD profiles enforced via nftables; captures device-to-device interactions | Real smart home traffic, multiple IoT protocols | Blocks unauthorized flows with negligible latency | Profiles must be manually authored — not scalable to consumer households |

### Theme B — SDN-Based Microsegmentation
| Paper | Method | Dataset | Result | Limitation |
|---|---|---|---|---|
| Osman et al., USENIX HotEdge, 2020 | SDN/NFV edge-cloud controller dynamically assigns devices to microsegments | Simulated smart home topologies, Mirai-infected device | 65.85% attack surface reduction, only 2.2% legitimate flows blocked | Policies are static and inventory-based — cannot react to real-time compromise |

### Theme C — ML-Based Intrusion Detection
| Paper | Method | Dataset | Result | Limitation |
|---|---|---|---|---|
| Wang et al., Electronics, 2023 | Transformer-based IDS fusing network flow data and IoT telemetry | ToN-IoT benchmark | 98.39% binary detection accuracy, outperforms classical ML | Treats each flow independently — no graph structure, no device-relationship signal |

*(Supporting papers also referenced: Sivanathan et al. 2019 — IoT device classification + publicly released MUD ground-truth profiles; Hamza et al. 2019 — SDN-based MUD activity monitoring for volumetric attacks; Meidan et al. 2018 — N-BaIoT autoencoder botnet detection; Neto et al. 2023 — CICIoT2023 large-scale attack benchmark.)*

---

## 4. Research Gaps

**Gap 1 — No system closes the loop from profiling to enforcement automatically.**
MUDgee generates profiles but requires human deployment. De Keersmaeker enforces profiles but requires human authorship. Both leave the human as the necessary link between observation and protection — the exact reason consumer adoption is near zero.

**Gap 2 — Microsegmentation is static and cannot respond to observed compromise.**
Osman achieves strong attack surface reduction but with pre-configured, inventory-based policies. When a device is compromised at runtime, segmentation doesn't adapt without human intervention.

**Gap 3 — ML-based IDS ignores inter-device relationships.**
N-BaIoT and Wang 2023 both operate on individual device flows in isolation. A compromised bulb probing a laptop may stay under every individual traffic threshold — but the bulb–laptop edge, which never existed before, is a clear signal that no existing ML IDS models or detects.

---

## 5. Problem Statement

> Home IoT networks lack an end-to-end system that automatically learns per-device behavioral baselines without human configuration, detects anomalies at both the individual device level and the inter-device relationship level, and autonomously enforces adaptive network isolation in response — a gap that static, rule-based, and manually configured solutions have consistently failed to close.

**In Scope**
- Network-packet metadata-based behavioral profiling (no DPI)
- Automated SDN-based microsegmentation response
- Graph-structured anomaly detection using GNN
- Validation on simulation testbed
- Real-world household prototype (Phase II)

**Out of Scope**
- Deep packet inspection of encrypted payloads
- Federated learning across multiple homes
- Production firmware deployment on consumer routers
- Custom GNN architecture design
- Reinforcement learning policy agents

---

## 6. Objectives

1. **Automatic Profile Generation** — Generate per-device behavioral profiles from passive traffic metadata and compare against ground-truth MUD profiles created by MUDgee (UNSW dataset).
2. **Live Relationship Graph** — Construct and maintain a device communication graph in Neo4j, updated every 60 seconds, accurately reflecting real-time topology changes.
3. **Anomaly Detection Performance** — Detect four target attack classes (port scan, lateral movement, data exfiltration, C2 beaconing) with a high detection rate and low false positive rate across all device types.
4. **Automated Response Latency** — Enforce device isolation via Open vSwitch within seconds of anomaly onset, measured from first malicious packet to VLAN enforcement.
5. **Baseline Improvement** — Demonstrate measurable detection gain over Wang et al. (2023)'s flow-only baseline, and attack surface reduction exceeding Osman et al. (2020)'s static 65.85% figure.

*(Working numeric targets used internally for design/justification, not stated as hard commitments on the reviewed slides: ~75% profile fidelity, ~85% detection rate, ~8% FPR, ~30s response latency — each has literature-backed rationale, see Section 11.)*

---

## 7. Proposed Methodology

### Stage 0 — Offline Foundation (no Mininet)
1. UNSW IoT PCAP dataset + CICIoT2023 dataset collected.
2. UNSW PCAPs replayed offline through Zeek → per-device flow features extracted.
3. Behavioral Profiling Engine computes robust statistics (median/IQR, 3σ outlier exclusion) per device type → produces a frozen MUD-like JSON profile.
4. Profile compared against UNSW's MUDgee-generated ground-truth profiles → **feeds Objective 1**.
5. GraphSAGE model trained offline on labeled graph-snapshot data from N-BaIoT + CICIoT2023 + UNSW → weights frozen once trained.

### Stage 1 — Live Testbed Construction
6. Mininet + Open vSwitch set up as the virtual home network; 8–10 virtual device types created (camera, bulb, TV, plug, laptop, phone, etc.).
7. Python traffic-generator scripts written per device type, mimicking dataset-derived behavioral patterns — these run continuously as realistic background traffic.
8. All OVS traffic mirrored to a Zeek sensor, producing structured flow logs every ~60 seconds.

### Stage 2 — Live Detection Loop (runs continuously)
9. Every 60s, new Zeek flows are fed to the *frozen* Profiling Engine → computes a **behavioral deviation score** per device (new destinations, volume z-score, protocol drift, etc.) — it does not relearn.
10. Same 60s window updates the live graph in Neo4j (nodes = devices, edges = observed communication flows with byte/protocol/timing attributes).
11. The frozen GraphSAGE model runs on the current graph snapshot + deviation scores → outputs a per-device **anomaly score [0.0 – 1.0]**, combining individual behavioral deviation and structural (relationship) anomaly.

### Stage 3 — Decision & Response
12. If anomaly score > threshold, the **Decision Engine** (if-else logic) selects a response tier:
    - Alert only
    - Rate-limit bandwidth
    - VLAN isolate (quarantine)
    - Full block
13. Decision is dual-routed to:
    - **Ryu SDN controller** → converts decision into an OpenFlow rule → pushed to Open vSwitch → enforced (target: within seconds of anomaly onset)
    - **LLM-based explanation module** → generates a plain-English alert for the homeowner
14. Both feed the **Web Dashboard**: live network graph, per-device anomaly score timeline, alert log, manual override controls.

### Stage 4 — Evaluation
15. Four attack scenarios injected one at a time into the running simulation: port scan, lateral movement, data exfiltration, C2 beaconing.
16. System compared against three baselines: Suricata (rule-based), a flow-only ablation (no graph component), and a Wang 2023 replication (transformer, no graph) — measuring detection rate, false positive rate, response latency, and attack surface reduction vs. Osman's 65.85%.
17. A **poisoned-baseline stress test**: deliberately compromise a device during the learning window and measure how well three defenses (hard constraint rules, cross-validation against clean reference datasets, robust statistical baseline estimation) limit contamination.

### Why This Isn't Circular
Mininet is **not** just a test harness — but it is also **not** where the profile or model is trained. The traffic scripts (Stage 1) generate realistic background traffic *designed from* dataset knowledge, but the Profiling Engine and GNN were already trained *offline* on real UNSW/N-BaIoT/CICIoT2023 data (Stage 0) before Mininet ever runs. Inside Mininet, both components operate in **frozen inference mode only** — they measure deviation from an already-learned baseline, they don't relearn it from the simulated traffic. This keeps the "automatic profile learning" claim honest and non-circular.

---

## 8. Techniques & Tools

### Algorithms
- **GNN for anomaly detection** — home networks are naturally graph-structured; lateral movement and port-scanning threats are relationship-level phenomena that flow-only models miss.
- **GraphSAGE architecture** — chosen over GCN/GAT based on 2025 comparative research showing GraphSAGE outperforming both on intrusion detection tasks; also supports inductive learning (handles new/unseen nodes — important since new devices join home networks over time).

### Datasets
| Dataset | Content | Purpose |
|---|---|---|
| UNSW IoT dataset | Real traffic (.pcap) from 28 IoT devices | Profile-engine training + ground truth |
| MUDgee MUD profiles | Expert-written MUD profiles for the UNSW devices | Ground truth for Objective 1 comparison |
| CICIoT2023 | Benchmark dataset, 33 attack types across large-scale IoT environment | GNN training diversity, especially lateral-movement-style attacks |

Purpose overall: **train the GNN** and **build realistic traffic simulation scripts** for Mininet.

### Platforms
| Tool | Role | Chosen over | Why |
|---|---|---|---|
| Mininet + Open vSwitch | Network emulation | GNS3, CORE, ns-3, real hardware | Real Linux network namespaces → real TCP/IP packets Zeek can capture; native OpenFlow support for Ryu integration |
| Ryu | SDN controller | OpenDaylight, ONOS, Floodlight, P4+BMv2 | Python-native, simple REST API, matches our all-Python pipeline |
| Zeek | Traffic analysis | tcpdump/Wireshark, Suricata, nfstream | Produces structured flow logs matching the format used by UNSW/N-BaIoT/research literature — keeps live features consistent with training features |
| Neo4j | Graph database | NetworkX, PostgreSQL, InfluxDB, MongoDB | Native graph queries (e.g., "new edges in last 60s") run in milliseconds; persists across restarts |
| PyTorch Geometric | GNN framework | DGL, StellarGraph, plain PyTorch | Dominant library in graph-ML research; GraphSAGE available out of the box with optimized sparse ops and inductive support |

---

## 9. Expected Outcomes

**Phase I — Software Prototype**
- Fully functional pipeline: traffic capture → profiling → graph → GNN → isolation
- Validated on Mininet testbed with 4 attack classes injected

**Phase II — Hardware Prototype**
- Same pipeline deployed on Raspberry Pi 5 in a live household
- Red-team attack emulation on real IoT devices

**Performance Metrics**
- **Profile Fidelity** — % of endpoints in UNSW ground-truth MUD profiles also captured by our auto-generated profile
- **Anomaly Detection Rate** — % of injected anomalies correctly flagged by the GNN
- **False Positive Rate** — % of false anomaly alerts raised
- **Automated Response Latency** — time between anomaly detection and rule enforcement
- **Attack Surface Reduction %** — reduction in reachable device pairs after network isolation, benchmarked against Osman's 65.85%

---

## 10. Timeline

### 7th Semester — Software Prototype & Pipeline Validation
| Month | Focus |
|---|---|
| July | Research |
| Aug | Data preprocessing and tool setup |
| Sep | Behavioral profiling and GNN training |
| Oct | Attack simulation, pipeline integration, evaluation |

### 8th Semester — Physical Prototype
| Month | Focus |
|---|---|
| Dec | Hardware setup & Pi deployment |
| Jan | Baseline learning for real profile generation |
| Feb | Attack emulation & real-world evaluation |
| Mar | Final touches & paper writing |

---

## 11. Numeric Target Justification (internal reference, not stated as hard slide commitments)

- **Profile fidelity ~75%**: Pasquini et al. (2025) report metadata-only profiling recovers 70–80% of stable endpoint patterns vs. DPI ground truth — no DPI, no encrypted payload inspection, so 100% is unrealistic; some endpoints are dynamic CDN addresses.
- **Detection rate ~85% (varies by attack class)**: Wang 2023's 98% is on *supervised binary classification with clean labeled data*; our task is harder — unsupervised, multi-class, graph-based, real-time. Port scans (large traffic spike) are easier (~90%+); C2 beaconing (tiny periodic packets) is harder (~80%).
- **FPR ~8%**: Published GNN-based anomaly detectors report 3.8–5% FPR on clean benchmarks; 8% is a realistic real-world (noisier) target, chosen because beyond ~10% FPR, home users start ignoring alerts entirely.
- **Response latency ~30s**: A standard TCP port scan takes 30–60s to complete; isolating within 30s contains the attack before it finishes. Internal budget breakdown: Zeek buffering (2–5s) + graph update (3–5s) + GNN inference (2–8s) + Ryu/OVS enforcement (<1s) ≈ 8–19s, leaving headroom under the 30s target.
- **Attack surface reduction > 65.85%**: Directly Osman et al.'s own reported figure for *static* microsegmentation — our hypothesis is that *adaptive* (GNN-triggered, runtime) isolation exceeds this because static policies can't react to a device that becomes compromised after deployment.

---

## 12. Team Roles

| Member | Focus | Responsibilities |
|---|---|---|
| **Anand Mahadev** | Network Infrastructure Engineering | Mininet testbed development, Open vSwitch and Zeek setup, attack simulations, SDN enforcement |
| **Sarveshwar Balu** | Data & Profiling Engineering | Traffic feature extraction, traffic simulation script development, behavioral profile engine, ground-truth profile validation |
| **Jayan Subramanian** | ML Engineering | Graph construction, GraphSAGE model, dataset preparation and GNN training, evaluation/validation/comparison |
| **Rashwanth Ram** | System Integration & Evaluation | Pipeline orchestration, decision engine development, evaluation framework, web dashboards |

---

## 13. References (IEEE Format)

[1] A. Osman, A. Wasicek, S. Köpsell, and T. Strufe, "Transparent Microsegmentation in Smart Home IoT Networks," in *Proc. 3rd USENIX Workshop on Hot Topics in Edge Computing (HotEdge '20)*, 2020.

[2] F. De Keersmaeker, R. Sadre, and C. Pelsser, "Supervising Smart Home Device Interactions: A Profile-Based Firewall Approach," in *Proc. IFIP Networking Conference*, 2024, pp. 413–422.

[3] A. Sivanathan et al., "Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics," *IEEE Trans. Mobile Comput.*, vol. 18, no. 8, pp. 1745–1759, 2019.

[4] A. Hamza, D. Ranathunga, H. H. Gharakheili, M. Roughan, and V. Sivaraman, "Clear as MUD: Generating, Validating and Applying IoT Behavioral Profiles," in *Proc. ACM SIGCOMM Workshop on IoT Security and Privacy (IoT S&P)*, 2018, pp. 8–14.

[5] A. Hamza, H. H. Gharakheili, T. A. Benson, and V. Sivaraman, "Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity," in *Proc. ACM SOSR*, 2019, pp. 36–48.

[6] Y. Meidan et al., "N-BaIoT: Network-Based Detection of IoT Botnet Attacks Using Deep Autoencoders," *IEEE Pervasive Comput.*, vol. 17, no. 3, pp. 12–22, 2018.

[7] E. C. P. Neto et al., "CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment," *Sensors*, vol. 23, no. 13, 5941, 2023.

[8] Y. Wang et al., "Securing a Smart Home with a Transformer-Based IoT Intrusion Detection System," *Electronics*, vol. 12, no. 9, 2100, 2023.

---

## 14. Key Conceptual Clarifications (for team reference / Q&A prep)

- **MUD Profile** = a "job description" for a device — what servers/ports/protocols it should normally use — traditionally hand-written by manufacturers; this project generates it automatically by observation instead.
- **Behavioral Profile Engine = the automated MUD profile engine.** Same thing, not two separate systems.
- **Anomaly detection vs. threat hunting**: anomaly detection is passive/reactive (waits for deviation to surface); threat hunting is active/investigative (asks specific questions of the graph). This project's GNN does the former; the LLM/decision layer does a scoped version of the latter.
- **Heterogeneous IoT**: devices from many vendors doing very different things — means no single "normal" baseline works; each device type needs its own learned profile.
- **Poisoned baseline problem**: if a device is already compromised during the learning window, the compromise becomes the new "normal." Mitigated by three layers: (1) hard, unpoisonable constraint rules derived from device-type priors, (2) cross-validation against clean external datasets (UNSW/N-BaIoT), (3) robust statistics (median/IQR, 3σ outlier exclusion) during baseline construction. Not fully solvable — an explicitly acknowledged limitation, and its handling is itself a research contribution.
- **Decision Engine** is deliberately simple — threshold-based if-else logic selecting from a fixed action menu, not an LLM freely generating network rules (that idea was explicitly rejected as unreliable/unsafe for a real network).

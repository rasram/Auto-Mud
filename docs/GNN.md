# AutoMUD — Model Engineering Roadmap
### (GNN Anomaly Detection Module — Self-Supervised GraphSAGE + Compromised-Device Classifier)

---

## 1. Overview

This document describes the machine learning core of AutoMUD: a system that watches a smart home's network traffic, learns what "normal" looks like for every device without any manual labeling, and flags devices whose behavior no longer fits that learned notion of normal — including two distinct failure modes: (a) a previously well-behaved device that starts acting strangely, and (b) a device that was compromised from the very first packet it ever sent, with no clean history to compare against.

The module sits between two other parts of the pipeline that are being built in parallel:

- **Upstream**: Zeek captures raw traffic → a profiling/graph-export pipeline turns this into per-device feature vectors, a live device-communication graph (in Neo4j, refreshed every 60 seconds), and a separately-computed per-device behavioral deviation score (from the profiling engine's MUD-like profile comparison).
- **Downstream**: this module outputs three graph/traffic-derived anomaly signals per device per 60-second window (reconstruction error, link-prediction score, classifier probability). These are **not** fused internally with the profiling engine's deviation score — all four signals are sent independently to a rule-based Decision Engine (alert / rate-limit / VLAN-isolate / block), which performs the final fusion, and which drives an SDN enforcement layer (Ryu → Open vSwitch).

Everything described below is *this module's* responsibility: turning the graph + feature snapshots into three interpretable anomaly signals, reliably and defensibly — deliberately stopping short of a single opaque blended score, so each signal's contribution to a flagged decision remains traceable.

---

## 2. The Model, Explained

### 2.1 The core idea

Rather than training a model to recognize "what an attack looks like" (which would require large amounts of labeled attack data and would only generalize to attacks resembling its training examples), the primary detector is trained to do exactly one thing very well: **reconstruct normal behavior**. It is shown only clean, non-malicious traffic during training. Because it is never shown attacks, it has no learned pathway for handling them — and this incapacity is precisely the anomaly signal. When a device's behavior drifts from its own established normal, the model's attempt to reconstruct it fails visibly, producing a large reconstruction error that we threshold into an anomaly flag.

This is powerful, but it has one structural blind spot: it can only detect deviation *from a device's own history*. A device that is compromised from the moment it joins the network never has a clean history to deviate from — its bad behavior simply becomes what the model thinks is normal for it. A second, complementary module — a supervised classifier trained on labeled attack patterns — is added specifically to close this gap. It does not rely on a device's own history at all; instead it recognizes known attack *signatures*, the way antivirus software recognizes a known malicious file pattern regardless of that file's history on a given machine.

The two modules together produce three graph/traffic-derived anomaly signals per device per window — deliberately kept separate rather than blended into one internal score:

1. **Reconstruction error** (a device's own current behavior vs. its own learned normal)
2. **Link-prediction score** (whether a current connection between two devices is structurally expected, given the graph's learned normal topology)
3. **Classifier probability** (whether current behavior resembles a known attack pattern, independent of history)

A fourth signal — the **profiling engine's behavioral deviation score** (how far current traffic departs from the device's stored MUD-like profile) — is computed entirely outside this module and is sent directly to the Decision Engine rather than being folded into the GNN's embeddings. This is a deliberate design choice, not an oversight: routing it around the GNN keeps each of the four signals independently interpretable (a flagged device can be traced to "graph-structural anomaly" vs. "raw-traffic reconstruction anomaly" vs. "known-attack-pattern match" vs. "profile deviation" rather than one opaque blended number), avoids making the GNN's training depend on the profiling engine's convergence timing, and adds a layer of redundancy — a simpler, rule-based signal that still functions even if the GNN is miscalibrated or undertrained on some edge case. The trade-off is that the profiling engine's deviation score and the GNN's reconstruction error (Head A) measure a similar underlying thing — "how far has this device drifted from its own history" — via different methods, so they may be significantly correlated in practice; this should be checked empirically once both are available, rather than assumed to add fully independent detection power. Note also that neither signal helps with the compromised-from-start problem, since both rely on the device having an established history to deviate from — that gap is closed only by Head C.

### 2.2 Architecture

**Shared encoder — GraphSAGE.**
Every 60-second window is represented as a small graph: one node per device, edges representing who is currently talking to whom. Each node carries a feature vector **x_v** (defined in Section 3) — deliberately limited to raw traffic-derived statistics (bytes, destinations, ports, timing, etc.); the profiling engine's behavioral deviation score is *not* included here, and is instead passed directly to the Decision Engine (see Section 2.1). GraphSAGE processes this graph by, for each device, sampling its current neighbors, aggregating their feature vectors (mean aggregation is the baseline choice), combining that aggregate with the device's own features through a learned transformation, and passing the result through a nonlinearity. Stacking two such layers lets each device's final representation — its **embedding, h_v** — incorporate information from its direct neighbors and its neighbors' neighbors. h_v is deliberately lower-dimensional than x_v, forcing the network to retain only the most useful, generalizable patterns rather than memorizing every input verbatim.

This single encoder is shared across all three downstream heads below — it is trained once (Stage 1) and reused everywhere else.

**Head A — Reconstruction decoder (self-supervised, node-level).**
A small MLP takes h_v and outputs **x̂_v**, an attempted reconstruction of the original x_v. Trained only on normal-traffic windows, minimizing mean squared error between x_v and x̂_v. At inference, high reconstruction error flags a device whose current behavior no longer matches the pattern the encoder learned to compress.

**Head B — Link-prediction scorer (self-supervised, edge-level).**
A second small module (e.g., a dot-product or bilinear function over pairs of embeddings) scores how "expected" a given edge is, trained by contrasting real edges against randomly sampled non-existent device pairs during training. At inference, a newly appeared connection between two devices that have structurally never interacted (e.g., a bulb suddenly talking to a laptop) receives a low expectedness score even if neither device's own traffic volume looks unusual — catching relational anomalies that per-device reconstruction structurally cannot see.

**Head C — Compromised-device classifier (supervised, added module).**
A third MLP takes the same h_v and outputs a single compromised-probability between 0 and 1. Unlike Heads A and B, this is trained with labeled examples (both normal and known-attack traffic), using binary cross-entropy loss. It is trained in a second, separate stage, on a **frozen** copy of the Stage-1 encoder, so its training does not disturb the carefully-learned "normal" representation the reconstruction task produced.

**Why not train a single end-to-end binary classifier instead of reconstruction?** A classifier requires both classes during training to learn any decision boundary; a model shown only normal examples during training would trivially learn to always predict "normal" for everything, since it never receives a gradient signal pointing toward what "abnormal" looks like. Reconstruction sidesteps this by never framing the task as classification — anomalousness emerges as a side effect of the network only being competent at one thing. Head C exists precisely because it *is* solving a genuinely different, two-class problem, where labeled data is a requirement rather than a workaround.

### 2.3 Dataset

**Source and shared pipeline.** Both this module and the profiling-engine module (owned separately) read from the same raw source: Zeek's `conn.log` and the Neo4j device-communication graph, refreshed every 60 seconds. This module builds its own downstream feature-extraction step rather than consuming the profiling engine's MUD-style JSON output directly, since that output is a slowly-updating summary (for MUD-profile comparison) rather than the fresh, per-window numeric vector this model needs to train and reconstruct against. Shared low-level statistics (e.g., "is this destination new") should be implemented once as a common utility both pipelines call, to avoid inconsistent duplicate logic.

**Training data comes from self-simulated Mininet traffic, not raw public-dataset replay.** The base GNN (encoder + Heads A & B) is trained on traffic generated by the team's own traffic-simulation scripts running inside the Mininet testbed — not on UNSW pcaps played back directly. This is a deliberate architectural choice, not a shortcut: real UNSW IoT traffic is overwhelmingly device-to-cloud (each device talking to its own manufacturer's servers), with very little genuine device-to-device traffic — so a graph built directly from it would starve Head B (link-prediction) of the relational structure it exists to model. The Mininet-simulated household, by contrast, is fully controlled, so device-to-device interactions can be deliberately scripted on top of a realistic device-to-cloud baseline, giving the graph actual structure to learn from. Public datasets (UNSW Traffic Traces, and later CICIoT2023/UNSW Attack Traces) instead serve two supporting roles: (a) **calibration** — offline Zeek analysis of UNSW pcaps yields real per-device-type statistics (byte volumes, destination counts, port/protocol distributions, active hours) that parameterize the traffic-generation scripts, so simulated traffic is statistically realistic rather than arbitrary; and (b) **ground truth / evaluation** — UNSW's MUD profiles remain the Objective 1 comparison target, and UNSW/CICIoT2023 attack data remains the evaluation and Head C training source, entirely separate from what trains the base GNN's weights.

**Per-device node features (x_v).** For every device, every 60-second window:
- Bytes sent / received (log-transformed — heavy-tailed distribution)
- Packets sent / received (log-transformed)
- Distinct destination count
- Fraction of connections to new (previously unseen) destinations
- Distinct ports contacted / port entropy
- Protocol distribution (TCP/UDP/ICMP fractions)
- Failed-connection or SYN-without-ACK rate
- Mean/median flow duration (log-transformed)
- Outbound/inbound byte ratio
- Time-of-day, encoded cyclically (sin/cos of hour, not raw hour number)
- Device type (static one-hot, concatenated)
- Activity flag (whether the device produced any traffic this window at all, paired with zero-filled features when inactive)

**Per-edge features (for Head B).** Bytes/packets exchanged on the edge this window, port/protocol used, a "new edge" binary flag, and connection frequency within the window.

**Normalization.** Z-score normalization computed **per device type**, not globally — a camera's and a smart plug's "normal" byte volumes are on entirely different scales, and global normalization would erase meaningful per-type variation.

**Splits.** Chronological, not random — random shuffling leaks information across highly correlated consecutive windows. Earliest portion of the learning phase → training; a later held-out normal-only slice → threshold calibration; the attack-injected evaluation period → held out entirely for testing.

**Training data for Head C specifically.** Head C additionally requires labeled attack examples. The primary source is self-simulated: attack scripts (built by the network-infrastructure teammate) run within the same Mininet/Neo4j pipeline, generating attacks that are automatically in the correct feature format, with unambiguous ground truth, and explicitly including "compromised-from-start" variants (attack behavior beginning at a device's very first packet, with no clean history). Public datasets (CICIoT2023, N-BaIoT, UNSW attack traces) are used secondarily, as a generalization check rather than a primary training source, due to the feature-schema reconciliation cost and lack of native graph/topology context in those datasets.

### 2.4 Training

**Stage 1 — self-supervised (encoder + Heads A & B).** Train on normal-only data using a combined loss (reconstruction MSE + link-prediction binary cross-entropy, weighted). Monitor convergence on a held-out normal validation slice before proceeding — both losses should be low and stable on unseen normal data, confirming the encoder has genuinely learned "normal" rather than overfitting to the training window's exact traffic.

**Threshold calibration.** Using the same held-out normal validation slice, compute the distribution of reconstruction errors and link-prediction scores, and set anomaly thresholds at a chosen percentile (e.g., 95th/99th) of normal-only values. This calibration must use only normal data — never attack data — to remain methodologically self-supervised and avoid indirectly "peeking" at the test conditions.

**Stage 2 — supervised (Head C only).** Freeze the Stage 1 encoder. Train only the classifier MLP on labeled normal + attack examples (including compromised-from-start scenarios), using binary cross-entropy. Freezing prevents Head C's supervised gradient from reshaping the reconstruction-optimized embedding space.

**Output handoff (not internal fusion).** This module does not combine its three signals into one internal score. Reconstruction error, link-prediction score, and classifier probability are each passed, per device per window, to the Decision Engine, which combines them with the profiling engine's independently-computed behavioral deviation score to make the final four-tier decision (alert / rate-limit / VLAN-isolate / block). Keeping fusion in the Decision Engine — outside this module — preserves per-signal interpretability and lets the Decision Engine's fusion logic (owned by the system-integration teammate) be tuned or re-weighted without retraining any model.

### 2.5 Evaluation

- **In-domain evaluation**: run trained models against self-simulated attack scenarios (4 attack classes × a representative subset of device types, not the full factorial), reporting detection rate and false-positive rate separately for each of the three signals (reconstruction error, link-prediction, classifier), since blending them into one number hides which mechanism is doing the work.
- **Compromised-from-start evaluation**: a distinct scenario category specifically testing Head C's contribution, since this is the one case Heads A/B structurally cannot solve.
- **Ablations**: GraphSAGE vs. GCN/GAT (architecture justification), and comparison against a flow-only baseline (approximating Wang et al.) to demonstrate the value of graph structure. Since fusion now happens at the Decision Engine rather than inside this module, "fused vs. individual signal" comparisons should be run as Decision-Engine-level experiments (coordinated with the system-integration teammate) rather than as an internal ablation of this module alone.
- **Deviation-score correlation check**: once both are available, measure the correlation between the GNN's reconstruction error (Head A) and the profiling engine's behavioral deviation score, since both measure a similar underlying signal via different methods — report this honestly rather than assuming the two add fully independent detection value.
- **Generalization probe (secondary, time-permitting)**: test the frozen model against a small slice of public-dataset attacks, using neighbor-context ablation and a neighbor-free baseline comparison (see Task 21) to attribute any performance drop correctly between genuine feature-level distribution shift versus synthetic-neighbor-context artifacts, rather than an unqualified single number.
- **Documented limitation**: Head C can only recognize attack patterns resembling its labeled training data (self-simulated and/or public); a truly novel attack style appearing from a device's first packet, with no resemblance to any known pattern, remains undetectable by design — stated explicitly rather than implied away.

---

## 3. Task Roadmap

Tasks are ordered to be completed sequentially where they build on one another; parallel tracks are noted where independent.

**Dependency note — what can start immediately vs. what waits on teammates.** Most of this roadmap does *not* require Anand's Mininet/OVS/Zeek testbed or Rashwanth's live Neo4j exporter to be finished first:

- **Fully independent, start now**: Tasks 1–2 (schema design), the UNSW calibration analysis referenced in Section 2.3 (your own offline Zeek run over UNSW pcaps — install Zeek locally, don't wait for Anand's deployment), Tasks 6–8 and 11–12 (encoder, Heads A & B, GCN/GAT variant, flow-only baseline), all of which can be built and unit-tested against synthetic/dummy graph data you construct yourself.
- **Blocked on Sarvesh + Anand**: real Stage 1 training (Task 10 onward) needs Sarvesh's calibrated traffic-generation scripts actually producing traffic inside Anand's running Mininet/OVS/Zeek testbed.
- **Interface dependency on Rashwanth**: the graph-snapshot exporter (Task 4) and Rashwanth's Neo4j→PyG export work are the *same interface* — agree on the exact `Data` object schema with him early to avoid building two incompatible versions. In the meantime, build your own temporary offline stand-in (a script producing PyG `Data` objects from Zeek `conn.log` + a manually-constructed edge list) so you can validate the encoder/decoder end-to-end on UNSW-derived data now, then swap in Rashwanth's live exporter once ready — same downstream code, different upstream source.

1. **Define and freeze the node feature vector schema (x_v)** jointly with the profiling-engine owner, using the field list in Section 2.3. Version this schema explicitly (e.g., `schema_v1`) so later changes don't silently invalidate stored data or trained models. *(Independent — start now.)*

2. **Define the edge feature schema** for link-prediction (bytes/packets per edge, port/protocol, new-edge flag, frequency), aligned with what the Neo4j graph-export step will actually provide. *(Independent — start now.)*

3. **Run the UNSW calibration analysis**: install Zeek locally and run it offline over UNSW Traffic Traces pcaps (not Anand's live deployment) to extract per-device-type statistics — byte volumes, destination counts, port/protocol distributions, active-hour patterns, flow durations. Hand these off to Sarvesh to parameterize the traffic-generation scripts, so simulated Mininet traffic is statistically realistic rather than arbitrary. *(Independent — start now.)*

4. **Build a temporary offline graph-snapshot exporter**: a standalone function converting Zeek `conn.log` output (from UNSW pcaps, plus a manually-constructed device-to-device edge list you define yourself) into a PyTorch Geometric `Data` object, matching the schema you'll later agree on with Rashwanth for the live Neo4j exporter. Unit-test this against fixed, hand-constructed sample data. This unblocks encoder/decoder development without waiting on the live pipeline; swap in Rashwanth's real exporter once it's ready, keeping all downstream code unchanged.

5. **Implement the feature-extraction/preprocessing pipeline** independently from the profiling engine: raw `conn.log`/Neo4j → per-device, per-window x_v vectors, including log transforms, cyclical time encoding, and per-device-type normalization. Coordinate shared low-level utilities with the profiling-engine owner rather than duplicating logic inconsistently.

6. **Establish the chronological train/validation/test split** once initial learning-phase data is available: earliest portion for training, a later normal-only slice for threshold calibration, and reserve the entire attack-injection period for evaluation only.

7. **Implement the GraphSAGE encoder** (2 layers, mean aggregator baseline) producing h_v from (x_v, current-window graph structure).

8. **Implement Head A (reconstruction decoder)**: MLP mapping h_v → x̂_v, with MSE loss.

9. **Implement Head B (link-prediction scorer)**: pairwise scoring function over (h_u, h_v), trained with negative sampling and binary cross-entropy.

10. **Run Stage 1 training** (encoder + Heads A & B jointly, weighted loss) on normal-only data. Confirm convergence and low error on the held-out normal validation slice before proceeding — treat this as a hard gate, not a formality.

11. **Calibrate anomaly thresholds** for reconstruction error and link-prediction score using percentile cutoffs on the held-out normal validation slice only.

12. **Implement a GCN or GAT variant** using the same two heads, for the architecture-choice ablation (justifying GraphSAGE's selection empirically rather than by citation alone).

13. **Implement a flow-only baseline model** (no graph structure — e.g., gradient-boosted trees or a small MLP on x_v alone) approximating Wang et al.'s comparison point. This can proceed in parallel with steps 7–11 since it doesn't depend on the encoder.

14. **Coordinate attack-scenario design** with the network-infrastructure/attack-scripting owner: specify the representative device subset per attack class, and explicitly request compromised-from-start variants for the classifier evaluation (Task 18).

15. **Implement Head C (compromised-device classifier)**: MLP taking frozen Stage-1 h_v as input, output a single compromised-probability. Assemble the labeled training set from self-simulated attacks (primary source) generated via Task 14's scenarios.

16. **Run Stage 2 training** (Head C only, encoder frozen) using binary cross-entropy on the labeled normal + attack dataset, including compromised-from-start examples.

17. **Implement the fusion logic** combining reconstruction error, link-prediction score, and classifier probability into one final per-device anomaly score, to be handed off to the Decision Engine.

18. **Run in-domain evaluation**: detection rate and false-positive rate, reported separately for (reconstruction/link-prediction) vs. (classifier) paths, across the representative attack scenarios from Task 14, plus the compromised-from-start scenarios specifically isolating Head C's contribution.

19. **Run ablation studies**: GraphSAGE vs. GCN/GAT (Task 12), fused vs. individual signals, and comparison against the flow-only baseline (Task 13), on the same evaluation scenario set for consistency.

20. **(Time-permitting) Public-dataset generalization probe**: map a small slice of CICIoT2023/N-BaIoT attack flows into the x_v schema; run the frozen model using (a) a neighbor-ablated pass (zero/self-loop neighbor context) and (b) the neighbor-free baseline classifier from Task 13, to attribute any accuracy drop between genuine feature-level distribution shift and synthetic-neighbor-context artifacts, before reporting a headline generalization number.

21. **Document results and limitations**: per-device-type and per-attack-class breakdowns (not just aggregates), explicit statement of Head C's known-pattern limitation, and — if Task 20 was completed — a clearly labeled in-domain vs. out-of-domain comparison rather than a single blended figure.

22. **Package model checkpoints, schema version tags, and normalization statistics** for handoff to the system-integration owner, ensuring the live inference pipeline can load and run the fused model without ambiguity about which schema version or training run produced it.
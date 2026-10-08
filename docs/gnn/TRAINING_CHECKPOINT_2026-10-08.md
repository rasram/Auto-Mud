# GraphSAGE A/B training and dataset checkpoint

**Checkpoint date:** 8 October 2026.
**Main project:** `C:\Users\Jayan\Coding\Projects\Auto-Mud`.
**Scope:** From the first supplied seven-day normal corpus and CUDA training through the original attack/control evaluation, robust v1 revision, local WSL setup, v2 experiment, and subsequent realism review.

This document records completed work, its evidence, and outstanding requirements. It is not a claim that the detector is ready for deployment. Numerical values below were checked against saved reports. The companion [evidence snapshot](evidence/TRAINING_CHECKPOINT_2026-10-08.json) preserves report summaries, input contracts, catalog fingerprints, checkpoint hashes, and source fingerprints because the original run directories are local Git-ignored artifacts.

## 1. Current position

- A/B training, calibration, inference, and frozen attack/control evaluation work on CUDA.
- The latest candidate uses `automud.graph.v2`: 38 measured features and 99 input columns, with external service context nodes.
- The v2 virtual experiment completed: 192 new scenario captures, 34 training epochs, and evaluation of 96 held-out attack/control runs.
- The checkpoint passed its normal-data engineering gate. Exfiltration actor-window recall is 87.14%; beaconing actor-window recall remains **0%**.
- Head B detects the defined scan/lateral positives but still produces substantial false alarms on other devices.
- A dedicated `automud` WSL distribution contains Mininet, OVS, Zeek, and a CUDA Python environment. A one-minute real Mininet pilot passed extraction and capture-quality checks after a UDP fix. Longer collections and real attack-detection performance remain unvalidated.
- Head C is implemented as a separate supervised training stage, but **none of the reported checkpoints has a trained Head C**.
- The current synthetic traffic is UNSW-informed, with substantial additional engineering assumptions. Its fidelity to UNSW/CIC distributions has not been established.

## 2. Terms and interpretation

| Term | Meaning at this checkpoint |
|---|---|
| Public captures | Original PCAPs published by UNSW/CIC and downloaded into the archive directories |
| Supplied normal capture | The seven-day Auto-MUD virtual-testbed corpus supplied before initial A/B training |
| Virtual capture | A synthetic packet recording generated on a virtual UTC clock; logical days need not take wall-clock days |
| Real Mininet capture | Packets sent through Linux sockets and OVS, captured with tcpdump using actual elapsed time |
| Prepared graph | A 60-second snapshot derived from measured interval telemetry |
| Validation loss | A reconstruction/link training-development measure; not intrusion accuracy |
| Normal test | Clean held-out observations used to measure false alarms; it contains no attack positives |
| Frozen attack test | Evaluation without changing the checkpoint, scaler, or thresholds |
| Population recall | Detected positives divided by all active known positives, including positive windows that a head could not score |

Head A detects behavioral deviation. Head B scores initiated relationships in the robust revisions. Head C identifies compromised actors, including devices compromised from their first observed event. Victims can exhibit unusual behavior without being compromised actors.

The GNN does not determine MUD authorization or update a device policy. Profiling deviation remains a separate signal for downstream decisions. Neo4j is unnecessary for the implemented graph-building path; Ryu enforcement is not part of these training experiments.

## 3. Timeline of completed work

Dates in run names identify the recorded run generation. Logical capture timestamps are separate from training dates.

| Stage | Data/model action | Main outcome |
|---|---|---|
| Initial data review | Inspect supplied normal collection and prepared v1 graphs | Sufficient to run A/B software training; insufficient to establish attack detection |
| Initial CUDA training, 2026-10-07 run | Train normal-only legacy GraphSAGE, calibrate on separate clean data, test on held-out normal day | Low normal-test false alarms; strong reconstruction/link validation losses |
| Original matrix review, 2026-10-08 | Audit 240 attack/control runs and evaluate the original frozen checkpoint on seed 5 | Severe false alarms under scenario/control conditions |
| Investigation | Inspect development controls/attacks and compare paired model inputs | Cold-start/scale sensitivity, victim-label mismatch, and almost identical exfiltration/beacon inputs |
| Robust v1 retraining | Reuse clean controls from the existing matrix; change model/scaling/calibration | Major reduction in benign-control alarms; exfiltration/beacon observability remained unresolved |
| Robust v1 matrix evaluation | Revisit the existing seed-5 test without training Head C | Strong scan/lateral detection; narrow Head B coverage; exfiltration/beacon missed |
| Local environment setup | Create dedicated WSL distribution and install tools after explicit authorization | Native local collection/extraction and CUDA computation available |
| V2 revision and run | Extend inputs, graph semantics, labels, and traffic plans; generate fresh scenarios | Exfiltration became detectable; beaconing and benign Head B alerts remain weaknesses |
| Real collection debugging | Diagnose UDP exchanges and run disposable Mininet pilots | UDP bug fixed; short pilot passed; an earlier longer retry stayed incomplete |
| Realism audit | Compare generation assumptions with calibration provenance and count added activities | Substantial unsupported generic additions identified; next revision should prioritize fidelity |

## 4. Original seven-day normal corpus

The persisted manifest identifies the supplied corpus as `source=virtual_testbed`, `synthetic=true`, and `clock_mode=virtual_packet_time`. It must not be described as seven days of real Mininet collection merely because the logical clock spans seven days.

| Quantity | Verified value |
|---|---:|
| Logical duration | 604,800 seconds / seven days |
| Logical study dates | 2024-01-01 to 2024-01-08 UTC |
| Device inventory | 12 devices |
| Minute snapshots | 10,080 |
| Device-window opportunities | 120,960 |
| Active device windows | 39,632 |
| Canonical telemetry rows | 155,411 |
| Unique observed flow UIDs | 150,237 |
| Packets | 856,284 |
| IP bytes | 340,404,132 |
| PCAP file size | 366,092,676 bytes |
| Canonical telemetry size | 71,813,135 bytes |
| V1 edge observations | 5,766 |

The inventory includes SmartThings, Echo, Hue, WeMo switch and motion sensor, Samsung camera, DropCam, doorbell, printer, weather station, air-quality sensor, and scale. The six household interaction relationships are authored testbed assumptions; they are not directly measured UNSW household edges. Device activity is uneven, so graph count alone overstates the amount of evidence for sparse device types.

Chronological normal partitions were fixed before training:

| Partition | Logical days | Graphs | Active devices | V1 edge observations |
|---|---:|---:|---:|---:|
| Stage-1 training | First four | 5,760 | 22,598 | 3,226 |
| Stage-1 validation | Fifth | 1,440 | 5,704 | 844 |
| Threshold calibration | Sixth | 1,440 | 5,731 | 868 |
| Normal test | Seventh | 1,440 | 5,599 | 828 |

Prepared graph hashes, feature validity, and source/session separation were checked. Metadata contained paths from the producer's Mac. Relative prepared-graph filenames allowed local training; those original absolute raw paths would require correction for re-preparation.

## 5. Initial model and CUDA implementation

V1 had eighteen traffic statistics, time sine/cosine, activity, eleven device-type indicators, and eighteen masks: `x[N,50]`, reconstruction targets `[N,18]`. Features included directional volume, flow counts, destination/port diversity, transport fractions, failure fraction, observed duration, and destination-history novelty.

The original model used two mean-aggregation GraphSAGE layers, `50 → 64 → 16`, a reconstruction decoder `16 → 64 → 18`, and a directed bilinear relationship scorer. The Head C classifier `16 → 32 → 1` existed but was untrained.

The training work added:

- Explicit CPU/CUDA device selection and a CUDA compute probe; an explicit CUDA request fails rather than silently falling back.
- Disconnected graph batching that preserves per-graph losses and manually offsets query pairs. Custom positive-pair tensors are excluded from automatic PyG batching.
- Vectorized counterfactual relationship scoring. The queried relationship is removed in both directions before scoring during training, calibration, and inference.
- Within-graph negative sampling that excludes known clean relationships; no negatives cross snapshot boundaries.
- Epoch timing, maximum-epoch ETA, progress JSON, best diagnostic checkpoints, durable logs, and run-status output.
- Safe checkpoint loading with `weights_only=True` and primitive dependency metadata.

The Windows `.venv-gnn` environment used Python 3.12, PyTorch 2.14.1+cu130, PyG 2.8.0.post1, NumPy 2.5.3, and the NVIDIA RTX 3050 with 8 GiB VRAM. GraphSAGE forward/backward and optimizer execution were verified on CUDA.

### Initial training result

Artifact directory: `data/gnn/models/virtual-ab-cuda-20261007/`.

| Measure | Value |
|---|---:|
| Epoch limit / patience / seed | 100 / 10 / 42 |
| Completed epochs | 49 |
| Minimum recorded validation epoch | 39 |
| Stage-one training duration | 184.80 seconds |
| Train/calibrate/normal-test duration | 195.10 seconds |
| Final validation reconstruction MSE | 0.00208705 |
| Mean reconstruction baseline | 3.98181864 |
| Final balanced validation link BCE | 0.00145437 |
| Engineering quality gate | Passed |

On the normal test, Head A flagged 76/5,599 observations: **1.3574% FPR**. Head B flagged 13/1,542 scored observations: **0.8431% FPR**. Normal specificity was approximately 98.64% and 99.16% respectively. These were not attack-classification accuracies. Precision, recall, and F1 are undefined for an all-normal target even when an older report emits zero placeholders; ROC/PR-AUC were unavailable.

Fast training was expected for small graphs and does not establish model quality. Low validation loss can coexist with poor detection on new normal conditions.

## 6. Addition of the original attack/control matrix

The supplied `data/gnn/virtual-prepared/catalog.json` contained 241 sources: the original normal source plus 240 scenario runs. Graphs and labels were available locally; original scenario PCAPs were not present in the main project during this evaluation.

The matrix comprised four families, three selected actors, five seeds, two onset modes, and attack/control pairs:

- Families: port scan, lateral connections, exfiltration-like transfers, and beaconing.
- Actors: Samsung camera, SmartThings hub, and WeMo switch.
- Seeds 1–3 development training, seed 4 validation, seed 5 test.
- Onset from the first event or after five clean minutes.
- Twenty minutes per run; 80 logical hours across all 240 runs.

Attack/control pairs shared a session and stayed in the same partition. The full catalog had 8,640 Stage-2 training graphs, 960 validation graphs, and 960 test graphs. Those partition names provided labeled evaluation data; they did not mean Head C had been trained.

The audit confirmed graph hashes, schema consistency, no test-session overlap, and agreement between the two copies of the original normal graph. The external evaluator also checked checkpoint/catalog binding, source reuse, complete windows, actor evidence, and unchanged checkpoint/scaler/thresholds. Stored remote capture hashes were compared for reuse; the remote original PCAP files were not independently inspected.

### Original model on the first matrix

Report: `data/gnn/evaluation/virtual-ab-20261008/report.json`.

The test had 48 runs, 24 paired sessions, 960 graphs, and 6,483 active known device windows. All 420 positive windows represented compromised actors in the original evaluation labels.

| Metric | Head A | Head B, scored windows |
|---|---:|---:|
| Scored windows | 6,483 | 3,300 |
| Coverage | 100% | 50.90% |
| TP / FP / TN / FN | 412 / 3,970 / 2,093 / 8 | 177 / 800 / 2,262 / 61 |
| Accuracy | 38.64% | 73.91% |
| Precision | 9.40% | 18.12% |
| Recall among scored positives | 98.10% | 74.37% |
| F1 among scored windows | 17.16% | 29.14% |
| FPR | 65.48% | 26.13% |
| ROC-AUC | 0.8130 | 0.8103 |
| PR-AUC | 0.2301 | 0.2160 |
| Population recall | 98.10% | 42.14% |

Matched controls alone had Head A FPR **46.91%** and conditional Head B FPR **13.49%**. Head A detected 24/24 episodes, but much of its apparent sensitivity occurred alongside widespread benign alarms. Head B detected 16/24; median latency among detections was 120 seconds, versus 60 seconds for Head A. Latency uses the completed minute-window decision, not instantaneous packet detection or Ryu enforcement time.

## 7. False-alarm and observability investigation

Development investigations used training/validation matrix portions. Sources are preserved under `data/gnn/ab-revision-investigation/`.

Findings included:

1. Clean controls had different startup/burst patterns from the original normal run. Training coverage did not represent these conditions well.
2. Destination novelty accounted for approximately 49.57% of control reconstruction residuals in the training portion and 39.69% in validation. Some type-specific scales were small, amplifying benign novelty.
3. Masking history reduced control flag rates diagnostically from about 46.94% to 18.65% in training and 46.11% to 17.78% in validation. This was an investigation, not a final calibrated solution.
4. Removing graph adjacency from the old model did not improve control false alarms. That out-of-distribution ablation did not establish that GraphSAGE itself caused all errors.
5. Scan/lateral victims often changed received traffic while retaining actor label zero. A behavioral alert on a victim was counted as a compromised-actor false alarm.
6. The original graph represented device-to-device relationships; external cloud communication affected aggregate features but had no scored relationship node.

The most decisive input comparison was:

| Development family | Positive windows | Identical complete model inputs to paired controls |
|---|---:|---:|
| Port scan | 420 | 0 |
| Lateral connections | 420 | 0 |
| Exfiltration | 420 | 402 / 95.71% |
| Beaconing | 420 | 404 / 96.19% |

The original controls and attacks often differed mainly by endpoint/port values, while model inputs retained counts, entropy, and aggregate volume. Different semantics therefore collapsed to identical features and adjacency. More layers or Head C cannot reliably distinguish identical inputs.

## 8. Robust v1 model and expanded normal coverage

This revision retained v1's 18/50 feature dimensions. It reused existing clean controls; it did not regenerate those training captures.

The expanded catalog had 97 sources: original normal data plus 96 controls. Seed 1–3 controls entered Stage-1 training; seed-4 from-start controls entered validation; seed-4 later controls entered calibration. All attacks and seed-5 sessions were excluded from fitting. Graph counts became 7,200 training, 1,680 validation, 1,680 calibration, and 1,440 normal test.

Implemented model/calibration changes:

- Residual self-feature paths and learned gates blend self and neighborhood representations.
- Layer normalization, 0.1 dropout, bounded standardized encoder input, and 15% denoising corruption of valid traffic features during training.
- Reconstruction loss restricted to active available devices.
- Robust scale floors: constant dimensions retain unit scale; nonconstant scales receive minimum floors to reduce excessive sensitivity.
- A separate relationship encoder uses stable type information and filters adjacency using clean-training type relationships.
- Robust Head B aggregates initiated relationships, instead of incident relationships at both endpoints.
- Normal calibration separates background from legitimate burst/cold-start contexts and takes conservative context quantiles, with pooled fallback for sparse groups.

### Two trained variants

| Measure | Robust v1 | Legacy architecture with expanded controls |
|---|---:|---:|
| Directory suffix | `ab-robust-cuda-20261008` | `ab-expanded-legacy-cuda-20261008` |
| Completed epochs | 100 | 30 |
| Minimum recorded validation epoch | 90 | 20 |
| Stage-one seconds | 551.25 | 162.46 |
| Full A/B run seconds | 569.92 | 182.42 |
| Final training reconstruction | 0.01024663 | 0.00307835 |
| Final validation reconstruction | 0.01075207 | 0.00328308 |
| Final training link BCE | 0.01363508 | 0.00179598 |
| Final validation link BCE | 0.01326504 | 0.01211003 |
| Normal-test Head A FPR | 11/5,599 = 0.1965% | 18/5,599 = 0.3215% |
| Normal-test Head B FPR | 4/800 = 0.50% | 0/1,542 = 0% |

Both passed the normal-data gate. The legacy expanded-data variant was an architectural comparison for normal validation, not a completed attack benchmark. Its zero normal-test Head B alarms must not be interpreted as perfect attack detection.

### Partially completed older-design fresh holdout

An earlier attempt generated 96 virtual captures under `data/collection/ab-fresh-holdout-20261008/`, using seeds 37/41 and the old scenario design. Extraction was partially completed; the session recorded 28 completed telemetry outputs, with no completed prepared catalog. This corpus did not produce the reported robust-v1 fresh-test result. It should not be confused with the later completed v2 corpus.

After the user requested prior permission for installation/data generation, that work was stopped. A later explicit authorization covered only evaluation of the already-present matrix; no new generation or installation accompanied that evaluation. The dedicated WSL setup and v2 generation were subsequently explicitly authorized.

## 9. Robust v1 on the existing matrix

Report: `data/gnn/evaluation/revised-existing-matrix-20261008/report.json`.

This revisited the seed-5 matrix already inspected earlier. It is labeled `revisited_test_after_architecture_development`; it is **not a fresh independent final benchmark**. Head B scope also changed.

| Metric | Head A | Robust Head B, scored windows |
|---|---:|---:|
| Scored windows | 6,483 | 726 |
| Coverage | 100% | 11.20% |
| TP / FP / TN / FN | 203 / 1,361 / 4,702 / 217 | 210 / 0 / 504 / 12 |
| Accuracy | 75.66% | 98.35% |
| Precision | 12.98% | 100% |
| Recall among scored positives | 48.33% | 94.59% |
| F1 among scored windows | 20.46% | 97.22% |
| FPR | 22.45% | 0% |
| Population recall | 48.33% | 50% |
| Population F1 | 20.46% | 66.67% |

Matched-control FPR fell to **0.4358%** for A and zero for B among its 264 scored controls. On paired actors, A had zero false positives, 48.33% recall, and 65.17% F1. The low aggregate A precision partly reflects victim behavior against actor-only truth.

Family recalls were A: scan 100%, lateral 93.33%, exfiltration 0%, beaconing 0%. B population recall was scan/lateral 100% and exfiltration/beaconing 0%. Both detected 12/24 episodes with 60-second median detected latency. High conditional B metrics concealed absent external relationship evidence; coverage and population recall are essential.

## 10. Dedicated local WSL environment

The existing Ubuntu installation was first inspected without modification. It started successfully as WSL 2, had Ubuntu 24.04.4, systemd enabled, roughly 15 GiB RAM, and GPU visibility. Its kernel exposed OVS modules, network namespaces, virtual interfaces, and traffic-control support. Mininet/OVS service, normal Zeek installation, and venv/pip packages were missing.

Following explicit authorization, a separate Ubuntu 24.04 distribution named **`automud`** was created from an official checksum-verified Ubuntu root filesystem.

| Item | Location/version |
|---|---|
| Distribution storage | `C:\Users\Jayan\WSL\automud\distribution` |
| Linux execution copy | `/home/jayan/Auto-Mud` |
| Main editable project | `C:\Users\Jayan\Coding\Projects\Auto-Mud` |
| WSL kernel | `6.6.87.1-microsoft-standard-WSL2` |
| Mininet | 2.3.0 |
| OVS | 3.3.9 |
| Zeek | 8.0.10 |
| Python environment | `/home/jayan/Auto-Mud/.venv` |
| PyTorch / CUDA runtime | 2.14.1+cu130 / 13.0 |
| GPU | RTX 3050, 8 GiB |

tcpdump, ethtool, mergecap, Python dependencies, and systemd-managed OVS were installed inside this distribution. No Neo4j/Ryu deployment or Linux NVIDIA driver installation was required. The normal `jayan` user has no preset password; interactive sudo needs a user-established password or an explicit root WSL invocation.

Checks passed: disposable Mininet ping test with 0% loss; exact Zeek packet/byte, handshake, failed-SYN, interval, and IPv6 fixture accounting; CUDA GraphSAGE forward/backward/optimizer execution; and ultimately 38 tests in WSL. The copied v2 checkpoint also loaded successfully on CUDA in Windows. A full Windows pytest attempt encountered temporary-directory permissions/cleanup problems; the target Linux suite is the verified full-suite result.

## 11. V2 schema, graph, labels, and model

### Features

V2 retains the original eighteen measurements and adds twenty:

- Local/external transmitted and received IP bytes.
- External-flow fraction and web/TLS-port/DNS/other-service fractions.
- Transmitted bytes per initiated flow.
- Flow-gap mean, coefficient of variation, and minimum.
- Maximum new-flow count within fixed ten-second bins.
- Preceding five/fifteen-minute byte means and five-minute flow mean.
- Log current-to-prior traffic changes and fifteen-minute gap variation.

The input is **99 columns**: 38 normalized features, three time/activity columns, twelve node types, eight service categories, and 38 masks. JSON contracts are in `configs/gnn/schemas/`. History starts empty at session boundaries and resets during unavailable observations. Rolling means exclude the current window; current-window events can contribute to gap statistics only after they have been observed. No future timestamps, scenario labels, raw IPs, or device-ID embeddings enter model inputs.

V1 telemetry/manifests remain accepted upstream, but v1 graphs and checkpoints are incompatible with the current v2 model dimensions. Keep historical artifacts and schema-compatible source separately; do not mix v1 scalers/checkpoints with v2 graphs.

### Graph semantics

Observed external communication creates context nodes grouped by service category, rather than identifying individual remote IPs. These participate in message passing and relationship scoring but are inactive as classified/reconstructed IoT devices. The eight categories are DNS, web, TLS-port, NTP, discovery, messaging, other TCP, and other UDP.

These are port/protocol hints. Synthetic traffic to port 443 is not necessarily TLS, and the current graph does not establish whether a particular cloud server is authorized.

### Label semantics

| Label | Target |
|---|---|
| `label` | Compromised actor; future Head C truth |
| `behavior_label` | Head A behavioral target, including planned affected-victim intervals |
| `relationship_label` | Head B unexpected initiated relationships |

In this experiment, scan/lateral actors are Head B positives; exfiltration/beaconing through the permitted service categories are Head B negatives. Victim annotations represent controlled-plan exposure, not proof of victim infection. Mixed/unknown boundaries are excluded.

### Model changes

The robust architecture consumes `99 → 64 → 16` inputs and reconstructs 38 targets. Its relationship encoder retains stable type and service context, while keeping traffic volumes out of the link branch. Residual/gated reconstruction, denoising, robust scaling, and counterfactual query removal remain. Head C masks additional rolling/history columns, but no Head C training was run. A persistent temporal hidden state was not implemented.

## 12. Revised traffic and the completed v2 experiment

The same collection framework was used, with revised plans. Existing seven-day packet files were retained; their telemetry was rebuilt into v2 graphs. New captures added generic polling/uploads and varied scenario timing/volume/services. This was **more than a feature-only change**.

A development pilot used seed 23, a Samsung camera, and ten-minute attack/control pairs for exfiltration/beaconing. Both families had zero identical complete model-input windows out of ten. That demonstrated observable differences for that pilot; it did not establish realism or reliable classification.

The main virtual run used three parallel capture/extraction workers and predeclared splits:

| Source subset | Runs | Logical hours | Use |
|---|---:|---:|---|
| Controls, seeds 11/13/17 | 72 | 24 | Clean A/B training |
| Seed-19 from-start controls | 12 | 4 | Validation |
| Seed-19 later controls | 12 | 4 | Normal threshold calibration |
| Seed-29/31 attacks | 48 | 16 | Frozen test |
| Their matched controls | 48 | 16 | Frozen test |
| Total new captures | 192 | 64 | Development plus evaluation |

All runs were twenty minutes. The 193-source catalog combined these with the original normal source. It contained 7,200 training graphs, 1,680 validation, 1,680 calibration, 1,440 original normal-test, and 1,920 attack/control-test graphs. Training had 37,848 active device windows and 56,805 external-service edge observations. These are correlated observations, not that many independent experiments.

Only clean data fitted A/B and their scaler. Thresholds used clean calibration; tests were evaluated after checkpoint freezing. Seeds represent new sessions of known families/devices, not proof of transfer to new device types or novel attack mechanisms.

### V2 training

Directory: `data/gnn/local-v2-run/`.

| Measure | Value |
|---|---:|
| Full collection/preparation/training/evaluation | 1,000.79 seconds / 16.7 minutes |
| Stage-one training | 596.63 seconds |
| Train/calibrate/normal-test | 624.55 seconds |
| Completed epochs | 34 |
| Final training reconstruction | 0.03910974 |
| Final validation reconstruction | 0.03989415 |
| Mean reconstruction baseline | 0.86006550 |
| Training / validation link BCE | 0.00814025 / 0.01794766 |
| Peak allocated CUDA memory | 612,165,632 bytes |
| Engineering quality gate | Passed |

The original held-out normal day had A FPR 59/5,599 = **1.0538%**, and B FPR 3/5,093 = **0.0589%**. The losses and sample coverage differ from v1, so numerical loss comparisons across feature revisions do not demonstrate improvement by themselves.

## 13. V2 frozen-test results

There were 96 runs, 48 paired sessions, 1,920 graphs, and 21,582 active available device windows. Head A had 4,287 behavior positives; Head B had 420 relationship positives.

| Metric | Head A | Head B |
|---|---:|---:|
| Scored windows | 21,582 | 21,226 |
| Coverage | 100% | 98.35% |
| TP / FP / TN / FN | 1,930 / 261 / 17,034 / 2,357 | 420 / 939 / 19,867 / 0 |
| Accuracy among scored windows | 87.87% | 95.58% |
| Balanced accuracy | 71.76% | 97.74% |
| Precision | 88.09% | 30.91% |
| Recall | 45.02% | 100% |
| F1 | 59.59% | 47.22% |
| FPR | 1.51% | 4.51% |
| ROC-AUC | 0.9112 | 0.99999 |
| PR-AUC | 0.7745 | 0.9996 |

The paired actor subset had 1,910 windows. A precision/recall/F1 were **99.66% / 70.48% / 82.57%**. B had 100% precision/recall/F1 for its defined relationship target on that narrow subset, but 939 false alerts elsewhere in the household. Selecting only actors would conceal that operational weakness.

| Family | A overall behavior recall | A paired-actor recall | B relationship recall |
|---|---:|---:|---:|
| Port scan | 42.53% | 100% | 100% |
| Lateral connections | 48.94% | 94.76% | 100% |
| Exfiltration | 87.14% | 87.14% | Undefined: no B positives |
| Beaconing | 0% | 0% | Undefined: no B positives |

Head A exfiltration F1 across all devices was 80.79%. Beaconing actor-level ROC-AUC was approximately 0.507, so a threshold adjustment alone is unlikely to resolve that failure.

Matched controls had A FPR **1.3691%** and conditional B FPR **4.3548%**. A detected 36/48 actor episodes; all twelve beaconing episodes were missed. B detected 24/24 scan/lateral episodes. Median completed-window decision latency among detections was 60 seconds.

For comparison with compromised-device truth, the report also retains an actor-only diagnostic across all devices: A precision/recall/F1 were 27.02% / 70.48% / 39.06%; B were 30.91% / 50% / 38.20%. These still use the new matrix and cannot be directly substituted for old-matrix performance.

## 14. Real Mininet pilots and transport fixes

Real pilots were infrastructure tests and were not added to the reported training or attack evaluation.

| WSL run directory | Study duration | Result |
|---|---:|---|
| `data/collection/local-mininet-pilot` | Three minutes | Incomplete; unexpected UDP exchange failures; zero capture drops |
| `data/collection/local-mininet-pilot-retry` | Three minutes | Incomplete; one agent did not finish by the collector deadline; zero capture drops |
| `data/collection/local-mininet-debug` | Planned one minute | Setup attempt failed because its diagnostic plan lacked the calibration checksum; no successful study |
| `data/collection/local-mininet-debug2` | One minute | Complete; all twelve devices active, no capture drops, no quality warnings |

The UDP bug was a client waiting for a reply even when the planned response length was zero. The responder now sends only nonzero responses; the client waits only for chunks that require a response. Tests cover a one-way datagram and a multi-chunk exchange with a zero-response tail.

Error logging now includes protocol, port, sizes, and exception type. Optional event-start/finish logs were added for diagnostics. All twelve agents in the successful pilot reported zero unexpected failures and zero late events. The collector's twenty-second drain bound remains in the current code; the earlier longer retry's completion failure was not conclusively resolved. A short successful pilot does not certify large-volume or multi-day collection readiness.

A subsequent scan-planner fix distinguishes provisioned open lab ports from closed ones; a successful connection to an open scan target should not invalidate the capture. This is tested in code, but a real revised attack matrix has not been evaluated. The completed v2 synthetic benchmark modeled selected scan ports as closed; it was not regenerated after this fix.

## 15. What changed in the dataset, and what did not

| Artifact | Change |
|---|---|
| Public UNSW/CIC files | No edits |
| Original seven-day virtual PCAP/telemetry | Retained; not rewritten to improve scores |
| Original normal graphs | Rebuilt into new v2 graphs in a new output directory |
| Robust-v1 training | Added existing clean controls from the original matrix |
| V2 development/evaluation | Added newly generated captures with revised traffic patterns |
| Evaluation targets | A/B behavior/relationship annotations separated from actor compromise |
| Historical results/models | Retained separately |

The new runs use the same planner/capture framework, but they are not simply additional samples of the original traffic design. The latest evaluation changes features, graph representation, scenario distributions, coverage, labels, and test sessions. A single before/after accuracy number cannot isolate an architectural benefit.

## 16. Realism review and its consequences

Original background generation draws service choices, sizes, durations, gaps, and hourly weights from `generator-profiles.json`, whose twelve sources identify UNSW normal devices. Its approximations include sixteen endpoint slots, ten-second durations, 64-KiB events, and one-hour gap caps. Independent draws discard dependencies between service, volume, and timing.

The v2 additions gave every device generic polling roughly every 25–120 seconds and 2–8 upload transfers of 8–64 KiB per burst. Short runs place a burst at minute one across devices. Common services are selected from ports 443/8080/8443/9090. These were engineering choices, not newly measured per-device application states. Cameras, scales, lights, and sensors should not automatically share those activities. Beacon destinations also vary between simulated endpoint slots, rather than modeling a documented persistent C2 stream.

The clean **training-control subset alone** had:

| Planned event kind | Events | Request + response payload bytes |
|---|---:|---:|
| Original/background `normal` | 26,575 | 47,315,112 |
| Added `normal_poll` | 17,904 | 41,240,832 |
| Added `normal_upload` | 4,584 | 210,644,160 |
| Added scenario `normal_control` | 5,870 | 10,585,125 |

Additional activities account for **51.62% of events and 84.73% of payload bytes in these 72 controls**. These are not whole-training-corpus fractions. All these captures are synthetic; the ratios distinguish old background scheduling from newly added assumptions, not real versus synthetic traffic. Background `normal` also includes authored household interactions.

Physical plausibility of sizes/rates does not establish similarity to real devices. No completed joint-distribution fidelity test supports calling the revised normal additions representative UNSW traffic. CIC and UNSW attack captures did not calibrate the latest four synthetic attack families. A dataset name such as `Uploading_Attack` or `Backdoor_Malware` is not sufficient evidence of our specific exfiltration or beaconing behavior.

The responsible present description is **UNSW-informed synthetic development traffic with explicit engineering scenarios**. Improved virtual scores do not establish realistic operational detection.

## 17. Agreed next recommendations: discussed, not implemented

1. Derive per-device idle/startup/interaction states from public normal recordings; replace universal polling/uploads with evidence-supported behavior. Retain unsupported generic activities as clearly identified stress cases.
2. Preserve measured service/size/direction/timing dependencies and long-lived flows when generating traffic. This requires changes to profile calibration, profile format, planning, and possibly transport rendering.
3. Add a realism comparison using the same extractor for public and generated captures. Compare per-device activity, services, directional volume, duration, timing, bursts, and joint behavior. Broad min/max agreement is insufficient.
4. Improve causal timing per peer/service stream and test temporal prediction or sequence encoding. Aggregating all device communications can bury beaconing; normal periodic polling must remain a control.
5. Improve representative normal coverage and type/context calibration for Head B. Excellent ranking with weak threshold precision is a reason to investigate calibration and coverage, not proof that threshold tuning alone solves the problem.
6. Compare node-only baselines, one/two GraphSAGE layers, and mean versus mean-plus-max aggregation. Additional spatial layers are not the first proposed solution to a temporal or identical-input problem.
7. Reserve fresh independent sessions, new actor/device roles, and real Mininet attack/control captures for later evaluation. Seeds 29/31 are now inspected and are not untouched final tests for future revisions.

Recommendations 1–3 are one cycle: define plausible behavior, generate it faithfully, then check it. Recommendation 5 depends partly on that cycle. There is no justified universal percentage limit on synthetic modifications; changes should increase measured fidelity rather than merely make attacks easier.

No persistent temporal encoder, per-peer beacon feature pipeline, empirically grounded activity-state generator, broad baseline study, or complete real attack/control benchmark has been completed at this checkpoint.

## 18. Public datasets and Head C status

Local reference directories are:

```text
E:\Projects_Archive\FYP\CICIOT2023\
E:\Projects_Archive\FYP\UNSW-IoTraffic\UNSW-IoTraffic\
E:\Projects_Archive\FYP\UNSW-IoTraffic\UNSW-IoT-Attack\
```

The user supplied/downloaded CIC victim metadata, UNSW `attackinfo.xlsx`, and UNSW attack PCAPs under `attack+benign-pcaps`. Victim identities are not sufficient compromised-actor ground truth. Compatible public training/evaluation requires verified actors, IP/MAC ownership, intervals, roles, and the same causal feature extraction. CIC extracted attack CSVs are not interchangeable with the graph input contract.

Head C training requires a clean-trained frozen encoder and both normal and verified compromised-actor examples, including from-start sessions. Public attack names alone cannot establish which device was compromised from the beginning. Equivalent observable normal/malicious traffic remains indistinguishable even to supervised C.

None of the A/B training runs depended on successful supervised public attack integration. The current v2 catalog intentionally leaves Stage-2 training/validation empty, so it cannot be passed directly to `train-all` to produce C. A complete predeclared catalog for both stages must be constructed first; checkpoint/catalog binding prevents silently adding C data to an unrelated artifact.

## 19. Artifact map, monitoring, and recovery

| Artifact | Main location |
|---|---|
| Original normal source | `data/collection/virtual-normal/` |
| Original normal-only catalog | `data/gnn/virtual-normal-prepared/catalog.json` |
| Original full matrix | `data/gnn/virtual-prepared/catalog.json` |
| Expanded v1 normal catalog | `data/gnn/ab-revision-prepared/catalog.json` |
| V1 investigation | `data/gnn/ab-revision-investigation/` |
| Original/robust-v1 evaluation | `data/gnn/evaluation/virtual-ab-20261008/`, `revised-existing-matrix-20261008/` |
| Latest reports/model/prepared graphs | `data/gnn/local-v2-run/` in Windows and WSL |
| New raw plans/captures | `/home/jayan/Auto-Mud/data/gnn/local-v2-run/` in WSL |
| Pilot quality report copy | `data/gnn/local-v2-run/local-mininet-pilot-quality.json` |
| Environment/tool guide | [LOCAL_WSL.md](LOCAL_WSL.md) |
| Compact latest result guide | [V2_RESULTS.md](V2_RESULTS.md) |

Model SHA-256 fingerprints:

```text
Original v1: 7d30b9217db333cbd77711281e6f0fff33ca699132494bd5b15bf85475140eb1
Robust v1:   bf705eafd6964a2404cb83ffe59ca1022d281775516fcc85ebd19407bfe7c02e
Expanded v1: d98362b2f38ffce01207f1a59084fe39ce5493988bbb7532a3abfe6f0024316c
Robust v2:   7569b09ca6d3272d5d1a2ffb71405de49ad00a3f736b0dd059c7c65854fee3c2
```

From PowerShell in the main project:

```powershell
.\scripts\gnn_progress.ps1
.\scripts\gnn_progress.ps1 -Watch
.\scripts\gnn_progress.ps1 -Json
```

The monitor reads status, capture counts, epochs, GPU, ETA, failure/completion, and process liveness; it does not train, resume, or restart a job. The completed v2 run reports `complete`. The background service was `automud-v2-training`; a WSL keep-alive process was created for conversation-independent execution. Pausing a conversation does not pause a job; shutting down WSL does.

`scripts/export_local_results.ps1` copies completed reports, models, and prepared graphs into the Windows project. New raw captures remain in WSL. Source changes must be synchronized deliberately between the main project and Linux execution copy.

Do not rerun the completed pipeline into its existing directory after generator changes; cached-plan/checksum guards reject mismatches. Use fresh directories and record the revised design. The monitor default is the current `local-v2-run`; use its `--run` option directly in WSL for another run.

## 20. Git/documentation boundary

This checkpoint documentation commit preserves this document, its evidence snapshot, and the supporting local-setup/latest-results documents. The evidence lists current source hashes, but **documentation is not a substitute for committing the implementation**. At document creation, GPU/evaluation/v1/v2 source changes remained unstaged working-tree changes relative to `5ce0660`; they are outside this documentation commit.

Model weights, PCAPs, prepared datasets, Python environments, and the WSL virtual disk are not committed. They are local artifacts; the evidence snapshot makes the reported conclusions readable without them. Preserve/export source and artifacts separately before moving the experiment or deleting a distribution. The old worktree at `C:\Users\Jayan\.codex\worktrees\e9d6\Auto-Mud` is not the authoritative current implementation.

This checkpoint creates no recurring automation and authorizes no further installations, collection, or training. Resume from the fidelity/coverage requirements above, with explicit task scope and new test sessions.

## 21. Reference material

- [UNSW-IoTraffic dataset](https://iotanalytics.unsw.edu.au/unsw-iotraffic.html): real-device PCAPs, flow statistics, and protocol models.
- [UNSW attack traces](https://iotanalytics.unsw.edu.au/attack-data.html): benign/attack captures and attack interval/flow annotations.
- [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html): documented attack families, lab topology, PCAPs, and extracted features.
- [GraphSAGE paper](https://arxiv.org/abs/1706.02216): neighborhood aggregation framework; architecture depth is an empirical choice for this application.

Public reference descriptions inform the proposed fidelity work. They do not independently validate the current synthetic normal additions or certify the saved model's operational performance.

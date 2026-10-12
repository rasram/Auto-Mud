# GNN evolution: Anand's first dataset to the selected New 2 package

Prepared 13 October 2026 for the AutoMUD team. This document explains the
implemented dataset, feature, architecture and scoring changes leading to the
GNN package selected for pipeline integration. It is a shared technical record;
the older datasets and development conversations are not needed to use it.

## 1. Which model this document describes

The selected package combines **native-clock/context Head A** with the **original
frozen Head B from the 9 October episode experiment**. A detects unusual device
behavior; B detects unusual initiated relationships. Head C, the proposed
compromised-device classifier, is untrained.

The selected A variant is `widened_native_mask30`, with
`prior_context_residual` scoring and the saved 5% clean-calibration tail.
“New 2” originally named the second new **development period** in a comparison
table. It was not a separate architecture or a model trained only on that period.
The package contains the checkpoint behind that row, subsequently evaluated on
a separate reserved corpus on 11 October.

“Hybrid” in this A model's architecture means **spatial GraphSAGE plus temporal
GRU forecasting**. It does not mean statistical-profiler/GNN fusion. The shared
package produces GNN-only evidence; the MUD engine remains a separate component.

## 2. Changes at a glance

| Aspect | First iteration | Selected package |
|---|---|---|
| Normal background | Supplied seven-day synthetic virtual-testbed corpus | Recorded UNSW packet backgrounds replayed into a household simulation, plus supported synthetic benign activities and broader source periods |
| Observation setup | Long normal collection; short scenario observers | Common 20-minute cold-observer episodes for fitting, calibration and scenarios |
| Graph contract | `automud.graph.v1` | `automud.graph.v4` for A; preserved v3 projection for B |
| Measured features | 18 | 50 for A; 44 for B |
| Node input columns | 50 | 123 for A; 111 for B |
| Explicit prior-window tensor | None | A: 15 windows × 24 columns, comprising 12 values and 12 validity masks |
| A architecture | Two-layer mean GraphSAGE and reconstruction decoder | Two-layer mean/max GraphSAGE with self paths and gates, plus causal GRU forecast; separate reconstruction/forecast decoders |
| A scoring | Masked mean squared reconstruction error | Normalized absolute residuals; average of largest three valid residuals per branch; maximum branch score |
| Time-of-day inputs | Virtual household/replay clock | Each device's original source time for recorded experiments; genuine UTC observation time for live inputs |
| Normal reference/calibration | Narrower normal coverage; type/global thresholds | Broader clean coverage; device and supported prior-context residual references; supported context/device/type thresholds and global fallback |
| B | Original relationship scorer sharing the behavioral encoder | Separate stable type/service relationship encoder; initiated-edge scoring; frozen episode checkpoint |
| Evaluation target | Originally compromised-actor labels used to assess A/B | Distinct behavior, initiated-relationship and compromised-actor labels; observed affected victims included in A |

The current 123 columns are 50 normalized traffic values, three clock/activity
columns, 12 node-type indicators, eight service-category indicators and 50
validity masks. A feature mask records whether a measurement is valid; a missing
measurement must not be treated as an observed zero.

## 3. What changed in the dataset

### 3.1 Anand's original macOS-produced corpus

The supplied source metadata contains `/Users/anand07/...` producer paths. Its
normal manifest explicitly records `source=virtual_testbed`, `synthetic=true`
and `clock_mode=virtual_packet_time`. It represents seven logical days, from
1–8 January 2024 UTC, rather than seven days of elapsed live Mininet collection.
That classification comes from the manifest, not from the producer's operating
system.

The original normal corpus contained 12 devices, 10,080 minute graphs, 155,411
telemetry rows and 856,284 packets. Its 120,960 possible device/minute observations
included only 39,632 active observations. The chronological split was four days
for normal training and one day each for validation, calibration and normal test.
The six local household relationships were authored testbed assumptions.

The first scenario matrix contained 240 twenty-minute attack/control captures:
four families, three actors, five seeds, two onset modes and matched counterparts.
The actors were Samsung camera, SmartThings hub and WeMo switch. The families
were port scanning, lateral connections, exfiltration-like transfers and beaconing.
Only clean data trained A/B; the scenario labels did not mean Head C was trained.

### 3.2 Why extending that corpus was necessary

Legitimate scenario controls had startup and burst patterns missing from the
long normal fitting collection. The first model consequently treated many benign
conditions as anomalies. Destination novelty and narrow normalization scales
contributed to this sensitivity.

There was also a representation problem: in the inspected development pairs,
402/420 exfiltration positive windows and 404/420 beaconing positive windows had
identical complete model inputs to their controls. Different destination/port
semantics were often lost when reduced to counts, entropy and aggregate volume.
Changing model depth cannot make identical inputs distinguishable.

The robust v1 revision therefore added existing clean controls to normal fitting,
validation and calibration. V2 rebuilt the original telemetry with richer features
and generated fresh scenarios with observable timing/volume/service differences.
V2 also added generic polling/uploads. A subsequent realism review found that
some of these additions lacked enough measured-device support; more generated
traffic alone was not a sufficient solution.

### 3.3 Move toward recorded packet backgrounds

V3 replaced independently sampled background statistics with recorded UNSW packet
replay and measured sequence evidence. Packet-derived Zeek observations retained
joint timing, direction, peer and service behavior. Universal synthetic polling
and uploads were removed from the default recorded-background preparation.
Authored household interactions and attack/control overlays remained explicit
simulation assumptions.

Chronological source partitions gained one-hour purge gaps. Later, the episode
revision made normal fitting and test scenarios use the same 20-minute observer
reset convention. This reduced the mismatch between a mature normal observer
and a newly started scenario observer. It did not certify physical device health
or make repeated backgrounds independent recordings.

V4 expanded clean calibration across source-day blocks, added supported benign
bursts, uploads, reconnects and service variation, and checked source packet
support before using an interval. Missing device activity remained a coverage
limitation. The source preparation was revised when some original device periods
had no usable packets; empty intervals were not padded into healthy traffic.

### 3.4 Data changes specifically behind the selected native-clock model

The final context study widened native source-period coverage while retaining
the existing benign-control parameters. It retained every new clean graph,
sampled every twelfth old clean training graph and every fifth old clean
validation graph, and retained eligible clean calibration evidence. This gave
the smaller new source pool meaningful representation without claiming copied
backgrounds were independent sessions.

The study added 27 clean captures: nine each for fitting, validation and
calibration across three new source days. It also compared the original
development period with two new matched matrices on different source days.
The other 11 devices used 14 additional unused packet-backed source days in the
reference preparation. Awair required a separate availability search, including
2018 UNSW captures: all annotated attack intervals, regardless of target device,
were excluded with a one-hour purge. Unannotated remaining intervals were clean
candidates; independently verified healthy operation remained unavailable.

Actual source intervals, previous exposure and packet support were audited before
selection. “Unused” refers to separation from previous fitting/calibration/
evaluation inputs, not merely a new filename or random seed. All 12 devices were
retained, with sparse observations and fallback support reported.

The selected final evaluation used 480 scenario captures in 240 matched sessions,
plus 100 standalone normal episodes over five source-day blocks: **11,600 graphs
and 92,511 primary active observations**. The later protocol used Echo, Hue and
Netatmo as scenario actors. New source dates, actors, labels and normal cohorts
mean its metrics are not a paired experiment against the first model.

### 3.5 Labels now match the individual heads

| Label | Meaning |
|---|---|
| Behavior target for A | Observed abnormal behavior, including affected receiving victims |
| Relationship target for B | Unexpected initiated relationships, principally defined scan/lateral events |
| Compromised actor label | Actor identity/compromise target for a future trained C head |

V4 checks planned malicious events against accepted Zeek flows. Unsupported
planned events are unknown, not automatically normal negatives. A receiver can
be behaviorally affected without being a compromised actor.

Regular malicious beacons and legitimate polling can still have indistinguishable
observable traffic. That challenge remains separately reported and outside the
predeclared primary distinguishable population. Primary metrics must not be
presented as detection of every beacon or every attack family.

## 4. What changed in feature extraction

All versions use completed 60-second windows. The extractor works with observed
directional packet/IP-byte deltas and causal timing/outcome fields, rather than
substituting a connection's final lifetime totals into earlier minutes.

| Graph revision | Added evidence | Measured values / input columns |
|---|---|---|
| V1 | Directional bytes/packets, flow counts, destination/port diversity, transport/failure fractions, observed duration, transmit/receive ratio and destination novelty | 18 / 50 |
| V2 | Local versus external volume, service fractions, bytes per initiated flow, flow gaps/bursts, prior 5/15-minute statistics and current-to-prior changes | 38 / 99 |
| V3 | Six per-peer/protocol/port stream features over one hour; explicit 15-window history for causal forecasting | 44 / 111 |
| V4 | Six receiver-focused features and four additional history values | 50 / 123 |

V2 also introduced external-service context nodes: DNS, web, TLS-port, NTP,
discovery, messaging, other TCP and other UDP. They participate in message passing
and relationship scoring but are not classified as IoT devices. These categories
are protocol/port hints; a TLS-port node does not prove encryption, maliciousness
or MUD authorization.

V3's stream features describe stream count, maximum starts, minimum gap
coefficient of variation, periodic-stream fraction, maximum age and concentration
of starts in the most active stream. They preserve longer timing evidence that
a single minute's totals lose.

The V4 receiver additions are:

| Feature | Information retained |
|---|---|
| `unique_initiators` | Number of distinct incoming peers |
| `new_initiator_fraction` | Incoming peers absent from prior observer history |
| `unique_inbound_ports` | Distinct incoming protocol/destination-port pairs |
| `inbound_failed_fraction` | Failed incoming TCP outcomes among known incoming outcomes |
| `inbound_flow_fraction` | Incoming flow intervals as a fraction of all device intervals |
| `inbound_flows_change_5m` | Current incoming starts compared with the prior five complete minutes |

The A history tensor contains 12 measured fields and their 12 masks for each of
15 preceding minutes. It excludes the current minute and future measurements.
Rolling references use prior complete windows; history resets on unavailability
or observation discontinuity. Healthy inactivity and unavailable observation
remain distinct states.

### Native clock correction

Original device recordings began at different UTC dates/times. Combining them
under one virtual household clock could show a device's normal activity at the
wrong hour. Fitting and later evaluation sometimes used different offsets.

The selected A normalizer calculates each recorded device's time-of-day from its
native source interval and observer age. The same offset applies to prior history.
Authored shared external-service nodes retain the replay clock. For live inputs,
the adapter uses the actual UTC window time. This is a change to time encoding,
not new training labels or a new B checkpoint.

## 5. What changed in architecture and anomaly scoring

### First A/B model

The first model had two mean-aggregation GraphSAGE layers, `50 → 64 → 16`, and
a reconstruction decoder, `16 → 64 → 18`. Its directed bilinear link scorer used
embeddings from the same encoder. A scored masked mean squared reconstruction
error. B initially aggregated incident relationship evidence, including receiving
endpoints. A `16 → 32 → 1` C classifier existed but was not trained.

### Robust changes retained by later models

Self-feature paths and learned gates let the model blend its own-device features
with neighbor messages. Layer normalization, 0.1 dropout, bounded standardized
traffic inputs and clean denoising masks were added. Scale floors limited excessive
sensitivity to almost-constant features. Only active available device observations
contributed to reconstruction fitting.

The relationship branch became separate: it uses stable type/service metadata and
clean-training type adjacency rather than current traffic-volume values. Each
queried relationship is removed from both adjacency directions before being
scored. Link training uses observed clean pairs and sampled nonrelationships;
known clean pairs are excluded from negatives. A low link-training loss establishes
that task's fit, not universal neighborhood anomaly detection.

### Selected Head A

The selected `BehaviorSAGE` configuration is two-layer **mean/max** aggregation,
hidden width 64, embedding width 16 and hybrid mode. Its spatial path consumes
123-column nodes and reconstructs 50 normalized values through a
`16 → 64 → 50` decoder.

Its temporal path is a GRU with 24 input columns per prior minute and a
16-dimensional hidden state. It forecasts the current 50 targets from prior
history plus clock/type/service metadata. Current volume, current activity and
current connectivity do not feed that forecast path. The spatial path still
uses the observed current graph.

Training masks 30% of valid current traffic inputs while leaving reconstruction
targets intact. Earlier robust/context variants used 15%. This encourages
reconstruction from other evidence instead of copying all current measurements.
**Random denoising corruption is a training procedure; inference runs the saved
model in evaluation mode.**

A computes absolute reconstruction/forecast errors, divides them by saved clean
residual scales, averages the largest three valid normalized errors per branch,
and takes the larger spatial/temporal score. This avoids averaging an unusual
channel away among many quiet features, but does not guarantee all anomalies are
detected.

The selected residual reference is device-conditioned and, where sufficiently
supported, conditioned on **strictly prior** observer age, flow load and
incoming/outgoing balance. Context groups require 200 rows, 30 source sessions
and 100 valid samples per feature. References shrink toward their parent with
1,000-observation weighting; context scales cannot be smaller than parent scales.
Sparse groups fall back to device, type or global references. Current anomaly
magnitudes, attack labels and future history do not choose the context.

Residual scales were fitted on clean validation; thresholds on separate clean
calibration. The selected clean tail is 5%, with supported context/device/type
thresholds and parent guards. A 5% calibration tail does not guarantee a 5% FPR
on later or live data.

The final controlled training comparison kept the architecture fixed and varied
legacy/native clock and 15%/30% masking on the same widened data. It also compared
device versus prior-context residual recipes on saved weights. None passed every
development gate. The selected setting was subsequently evaluated diagnostically;
its failed gates remain recorded.

### Frozen Head B

B comes from the 9 October robust, two-layer mean GraphSAGE episode checkpoint.
That artifact also contains an older behavioral forecast branch, but the shared
package uses its **relationship branch** for B. A's new GRU and clock/context
changes do not retrain B.

The adapter deterministically projects V4 back to V3 by dropping only the new
receiver/history fields. B retains its original weights, scaler, relationship
semantics and calibrated thresholds. It scores negative link logits and takes
the maximum over a device's initiated observed relationships. No eligible
initiated relationship means B is unscored, not confidently normal.

## 6. What the measured results establish

The initial held-out normal day had A FPR 1.3574% and B FPR 0.8431% among scored
observations. Since that test contained no attacks, these were normal false-alarm
measurements, not attack-classification accuracy.

On the first frozen attack/control matrix, A precision was 9.40%, recall 98.10%
and FPR 65.48%. B precision was 18.12%, conditional recall 74.37% and FPR 26.13%,
with 50.90% coverage; its population recall was only 42.14%. Good normal training
losses had not resolved scenario/control shift or lost input distinctions.

The selected package's saved primary final results are:

| Metric | Selected A | Frozen B |
|---|---:|---:|
| Precision | 83.3898% | 99.6194% |
| Recall | 89.8468% | 99.7143% |
| F1 | 86.4980% | 99.6668% |
| False-positive rate | 5.2804% | 0.009225% |
| Coverage | 100% | 96.0091% |

These are GNN-only scores on the selected saved population. A exceeds the 5% FPR
cap and falls below the 90% maintained-recall target. Its standalone-normal FPR
was 7.4983%, versus 4.8165% on matched benign controls. Aggregate results do not
establish equal performance in every normal cohort.

The datasets, normal conditions and head-specific truth populations changed over
development. The initial versus selected numbers therefore document successive
system evaluations; they do not isolate the gain from GraphSAGE, the GRU, native
time or one feature. Frozen B's high score on this corpus also does not establish
transfer to every new benign neighborhood. Physical healthy-activity verification,
source continuity and accuracy on a new live deployment remain unproven.

## 7. What teammates should carry into the pipeline

Use the selected bundle with its matching extractor, ordered feature contract,
scalers, residual references, thresholds and frozen B projection. A checkpoint
alone is insufficient if upstream measurements change meaning or order.

The model receives graph features derived from traffic; neither a training dataset
nor a profiler score is required as live input. The public reference fixture is
a loading/output-reproduction test, not a training set or a reproduction of the
aggregate evaluation. Keep A/B scores, flags, coverage and unscored reasons
separate; neither score is a compromised-device probability or a MUD permission.

For integration and installation, use the shared pipeline handoff and Linux setup
guides. This evolution document records the model's development; it does not
replace the service/input contract or assign automatic enforcement policy.

## 8. Evidence and model identity

This document was checked against the original supplied normal manifest/source
list, original frozen evaluation report, archived training/episode/context study
records, selected checkpoint metadata and current feature/model/scoring code.
Historical run identifiers are `virtual-ab-cuda-20261007`,
`virtual-ab-20261008`, `local-v2-run`, `v3-replay-study-v1`,
`episode-sage-once-20261009`, `a-precision-cycle-20261011`,
`a-context-iteration-20261011` and `a-context-final-20261011`. Historical source
data remains archived privately; teammates do not need it for this explanation
or live inference.

The Git-eligible bundle manifest and results report are the shared source of truth
for the selected artifacts. Verified SHA-256 identities:

| Artifact | SHA-256 |
|---|---|
| Selected composite A, including frozen B | `4a233d667d8ec81d21891845c95a27948e5283f105a2ecce93b64d88245e7698` |
| Original frozen B | `a996d926c634d4d4f3acc326ab748c962ea9ced561472f6c0d2717a9d4c00f7d` |
| First calibrated V1 checkpoint, historical identity only | `7d30b9217db333cbd77711281e6f0fff33ca699132494bd5b15bf85475140eb1` |

Implementation symbols available in the shared package include
`ml.schema`, `ml.ab_targets.schema`, `ml.ab_targets.tensors.Normalizer`,
`ml.ab_targets.model.BehaviorSAGE`, `ml.ab_targets.context_scoring`,
`ml.ab_targets.scoring.FrozenLink`, `ml.model.graphsage.Detector`,
`ml.clock.native_offsets` and `ml.inference.GNNBundle`.

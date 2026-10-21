# AutoMUD: presentation-ready results

Prepared 21 October 2026. This source contains the model benchmark, MUDgee comparison, and the bounded 21 October pipeline evaluation. Use the later consumed benchmark for the main model comparison; keep the earlier corpus and detailed breakdowns in backup material. Model benchmark, controlled MUD audit, and runtime qualification are separate experiments.

## Slide 1 — Supervised model benchmark

**Question:** How does the final supervised GNN compare with the initial supervised model and the selected baselines?

Later corpus: 460 captures, 9,200 graphs, 12 known devices. All entries are percentages, rounded to two decimals.

| Model | A precision | A recall | A F1 | B precision | B recall | B F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Initial supervised C | 99.14 | 99.43 | 99.28 | 99.90 | 99.57 | 99.74 |
| Final supervised E1+Q | **99.67** | 99.38 | **99.52** | **100.00** | **100.00** | **100.00** |
| Statistical profiler P | 99.27 | **99.59** | 99.43 | 99.72 | **100.00** | 99.86 |
| Strict device-local gradient boosting F | 80.92 | 96.53 | 88.04 | 95.58 | 80.33 | 87.30 |

**Takeaway:** E1+Q has the highest F1 for both heads among the four selected methods. Its A precision improvement comes with slightly lower recall than C and P.

**Speaker notes:** A detects behavioral/affected-device anomalies; B detects initiating-relationship anomalies. C disables learned graph messages but retains graph-derived descriptors. F excludes graph-informed and peer/service inputs; it is a strict own-traffic baseline, not the best possible non-GNN model. F used frozen fallback operating points after development cutoff constraints failed. A coverage is 100%; B coverage is 98.75% for all methods. B's 100% values apply to this benchmark and do not establish perfect real-world detection. These are previously consumed, known-device results from one authored household, not independent live accuracy.

## Slide 2 — MUD engine: comparison with MUDgee and policy correctness

**Question:** How closely do AutoMUD profiles recover the published MUDgee reference facts, and does the policy engine classify controlled connections correctly?

### Comparison with MUDgee-generated reference profiles

AutoMUD's Zeek behavioral profiles were compared with the published UNSW MUDgee-generated reference profiles for 27 devices. The comparison measures recovery of reference domains, transport ports, and networks.

| Result | Value |
| --- | ---: |
| Devices compared | 27 |
| Reference facts recovered | 359 / 465 |
| Overall reference-fact recall (micro) | **77.20%** |
| Mean per-device reference-fact recall (macro) | **85.10%** |
| Devices with complete checkable-fact recovery | 9 / 27 |

**Takeaway:** AutoMUD recovered 77.20% of the checkable MUDgee reference facts, averaging 85.10% recovery per device.

**Speaker notes:** Micro pools all checkable facts; macro weights devices equally. This is agreement with published MUDgee-generated profiles, not a new side-by-side MUDgee execution or attack-detection accuracy. The 465 items are checkable facts, not 465 complete ACL rules. Local-network and controller permissions are excluded from this denominator. Reference recovery does not measure false allowances or over-permissiveness. These frozen profile results predate later profiling fixes; no regenerated metrics are claimed.

### MUD expected versus observed decisions — new offline audit

The deployed MUD implementation was evaluated on **76,154 retained new-flow records**, using original Zeek telemetry and an independently enumerated reference for the six existing local permission rules.

| MUD result | Count |
| --- | --- |
| Correctly denied forbidden local records (TP) | 9,937 |
| Incorrectly allowed forbidden local records (FN) | 0 |
| Incorrectly denied permitted local records (FP) | 0 |
| Correctly allowed permitted local records (TN) | 873 |
| Correct local decisions / local records with defined permission | 10,810 / 10,810 (100%) |
| Records without a supported binary permission result | 65,344 / 76,154 |
| Overall binary-permission coverage of retained records | 14.19% |

**Takeaway:** All defined local-policy decisions agreed with the reference, but this does not establish complete household policy coverage.

**Speaker notes:** Actual unknown outcomes were 54,135 `unknown_device` and 11,209 `unknown_policy`. The original capture inventory identifies 48,369 of those unknown-device origins as household aliases absent from the deployed primary-only bindings; 5,766 origins are outside the household. The full-identity oracle categorizes 59,578 records as lacking a supported external policy and 5,766 as outside-household origins. Unknowns are neither correct denials nor TN. Counts are retained new-flow records, not all generated attempts; raw PCAP extraction/completeness was not retested. No policy or inventory was expanded to improve these figures.

## Slide 3 — Integrated offline correctness: predictions versus known truth

**Scope:** 57 existing recordings: **27 attacks + 27 matched benign controls + 3 standalone normals**, across **12 devices**, the three original actors and port-scan/lateral-connection/exfiltration families. There are **1,140 scored graphs**, **13,680 household device-windows**, and **13,389 eligible active device-windows**. The 291 inactive observations per head are excluded under the original protocol; none has a positive label.

New inference used the frozen E1+Q model and unchanged original tensors, including their native clocks, causal history and eligibility masks. Original telemetry was aligned by run/session/minute and processed by the actual MUD and decision implementations with a declared historical evaluation clock. The attack cases are the predeclared from-start subset with their existing cold/continuous histories; later-onset variants are not included. This subset belongs to the already consumed later corpus; it is not a fresh generalization study or an improvement over the full benchmark population.

| Head | TP | FP | TN | FN | Precision | Population recall | Population F1 | Coverage |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | 3,824 | 13 | 9,543 | 9 | 99.66% | 99.77% | 99.71% | 100.00% |
| B | 360 | 0 | 12,820 | 0 | 100.00% | 100.00% | 100.00% | 98.44% |

B additionally has **209 unscored negative observations**, which are not counted as TN. Neither head has an unscored positive.

| Known simulated attack actor | A actor episodes detected | B actor episodes detected |
| --- | --- | --- |
| Amazon Echo | 9/9 | 6/6 |
| Netatmo Weather Station | 9/9 | 6/6 |
| Philips Hue | 9/9 | 6/6 |

**Takeaway:** All **27/27 A actor episodes** and **18/18 applicable B episodes** were detected within the declared 180-second offline deadline, despite **9 missed A-positive windows** and **13 A false-positive windows**. Median offline episode-detection delay was **60 seconds** for both heads; maximum was 180 seconds for A and 60 seconds for B. All 30 benign/control recordings had zero A/B model flags on their eligible observations.

**Speaker notes:** A is behavioral/affected-device evidence, not a compromised-device classifier. B describes initiating relationships. Actors are authored simulation roles, not confirmed malware infection; affected victims remain distinct. A device can be correctly flagged in one minute and missed in another. Offline window-end detection delay is not live packet-to-enforcement time.

### Response proposals versus truth and policy

| Expected outcome at device-window level | Observed count |
| --- | --- |
| Required block correctly proposed | 360 |
| Required alert correctly proposed | 5,395 |
| Required alert missed | 1 |
| Correct no-proposal outcome | 7,633 |
| Unnecessary intervention proposals | 0 |

Binary proposal-presence confusion counts: **TP 5,755; FP 0; TN 7,633; FN 1** across 13,389 eligible device-windows. The missed alert was **Philips Hue during an exfiltration actor window**, case `045-observe`, original timestamp `1724016000`. It was missed by the model in that window; the actor episode was detected later.

The independent response matrix agreed with the actual decision implementation in **1,140/1,140 windows**, covering **12,740 flow/device proposals**, with **zero cooldown discrepancies**. All 1,140 windows correctly retained engineering/observe withholding; **zero offline proposals became installed actions**.

**Speaker notes:** Response truth requires an alert for an independently identified policy violation or A anomaly, and a block proposal for a forbidden initiating relationship with positive B truth. Thus proposal TP includes legitimate policy alerts during benign traffic and must not be called an attack TP. Code conformance uses actual model/MUD inputs; truth-based response quality tests whether useful evidence was present. These are different questions. Decision state starts empty for each scored recording; cooldown is evaluated in original chronological time within those 20-minute scored periods, while pre-score decision-state history is not reconstructed. Original detector history is preserved in the frozen tensors. HTTP/finalizer/async-join transport is not exercised in this offline layer.

## Slide 4 — Fresh live controller verification, separately measured

**21 October 2026:** three predefined engineering repetitions on an isolated switch/controller. Exact scope: **Amazon Echo → August Doorbell, TCP 18080**; Belkin WeMo Motion Sensor was the unaffected source. These requests were predefined controller checks, not actions triggered by the offline predictions.

| Live result | Verified outcome |
| --- | --- |
| Target reachable before intervention | 3/3 checks |
| Unique rules installed and barrier-confirmed | 6/6 |
| Target blocked during intervention | 6/6 checks |
| Unaffected source remained reachable | 3/3 checks |
| Rules expired / explicitly revoked | 3 / 3 |
| Target restored after expiry/revoke | 6/6 checks |
| Duplicate request reused its action cookie | 3/3 |
| Original services active after cleanup | 5/5 |
| Temporary evaluation switch removed | Verified |

Controller acceptance-to-barrier time for the six installs: **median 1.50 ms; range 0.97–1.73 ms**. This is a small controller-mechanics measurement, not end-to-end attack-response latency. The live check itself took **29.4 seconds**.

**Takeaway:** The exact scoped rules blocked the intended traffic, preserved the tested unaffected path, and restored connectivity. These small probe counts do not establish a general 100% blocking rate or household-wide collateral-traffic safety.

## Slide 5 — Discussion: what has and has not been established

| Layer | Current evidence |
| --- | --- |
| Frozen detector versus known truth | Offline evaluated; independently recounted; original flags reproduced |
| MUD versus independent policy lookup | Offline local decisions verified; substantial external/binding coverage gaps retained |
| Actual decision code and cooldown | Offline evaluated with explicit historical clock; proposals and observe withholding checked |
| Scoped controller effect and restoration | Fresh live engineering verification passed |
| Same labelled packets → GNN/MUD → automatic action → measured network effect | **Not established by this shortened study** |
| Fresh fully warmed live GNN attack study / live packet-to-enforcement latency | **Not measured** |

**Conclusion for the presentation:** The frozen detector, local MUD decisions, response logic and scoped controller mechanics have supporting evidence. The remaining limitations are external/alias policy coverage and validation of the complete automatic response chain on the same labelled live packets.

**Validation:** The offline pass took **75.1 seconds**. An independent standard-library recount verified all **27,360 A/B prediction records** against saved original reference labels, status and opportunity masks: **0 flag mismatches**, maximum logit difference **0.00000763**. Frozen model/policy/feature assets remained unchanged. The prior 43-hour protocol was stopped with its 13 accepted windows retained; it is not reported as a completed study.

The one-hour replacement was bounded from **16:35:45 to 17:35:45 UTC on 21 October** (22:05:45–23:05:45 IST). The final receipt records **26 minutes 49 seconds total**, including preparation, execution, verification and reporting. Existing datasets, assignments, labels, checkpoint, thresholds, profile and normalization were not modified; no new attack collection or training occurred.

## Sources for slide preparation

- [Frozen model benchmark and deployment limits](../gnn/MODEL_RESULTS.md)
- [MUDgee reference-fact comparison](../../data/processed/unsw/reports/zeek_reference_fact_recall.json)
- [Verified pipeline aggregate counts and evidence hashes](results-summary.json)
- [Shared recount tools and native pipeline checks](../../scripts/integrated_evaluation/README.md)

The tables above are self-contained for slide preparation. The strict device-local
F results come from the frozen 18 October report; its SHA-256 is recorded in the
aggregate summary. Original datasets, detailed per-record evidence, the dated
integrated evaluation plan and personal run-progress tools remain private. The
aggregate summary preserves evidence hashes for traceability; it does not bundle
the raw corpus or make it reproducible from a fresh checkout alone. Teammates can
use the shared tools with separately available labelled records and their configured
deployment. This publication does not rerun or change the measured study.

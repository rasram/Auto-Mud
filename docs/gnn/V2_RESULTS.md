# Local v2 A/B development results — 2026-10-08

The local virtual experiment completed in 1,000.8 seconds (16.7 minutes).
It generated/extracted 192 twenty-minute scenario captures, rebuilt the original
seven-day clean corpus with the expanded schema, and trained on the RTX 3050
using PyTorch 2.14.1+cu130. Training stopped after 34 epochs; stage-one training
took 596.6 seconds. Head C was not trained.

These are frozen-test results on revised virtual sessions with seeds 29/31.
They are not real Mininet detection results or a comparison on the old matrix.
After this evaluation was inspected, those sessions are no longer an untouched
test for future model/threshold development.

| Metric | Head A: behavioral anomaly | Head B: unexpected initiated relationship |
|---|---:|---:|
| Accuracy among scored windows | 87.87% | 95.58% |
| Precision | 88.09% | 30.91% |
| Recall | 45.02% | 100.00% |
| F1 | 59.59% | 47.22% |
| False-positive rate | 1.51% | 4.51% |
| ROC-AUC | 0.9112 | 0.99999 |
| PR-AUC | 0.7745 | 0.9996 |
| Scoring coverage | 100.00% | 98.35% |

Head A truth includes affected victims' annotated behavior windows. Head B truth
contains scan/lateral actor relationship windows; exfiltration and beaconing through
the permitted service categories are not Head B positives. There are 21,582 active
available device windows, 4,287 Head A positives and 420 Head B positives.

On the paired actor subset, Head A precision/recall/F1 are 99.66%/70.48%/82.57%.
Head B scores all actor windows and achieves 100% precision/recall on its defined
relationship target in this simulation. That narrow result does not eliminate the
939 Head B false alerts elsewhere in the household.

Head A exfiltration recall is 87.14%, with F1 80.79%. Beaconing recall is **0%**.
All 12 beaconing episodes were missed. Head A detects 36/48 total actor attack
episodes; Head B detects 24/24 scan/lateral episodes. Median decision latency among
detected episodes is 60 seconds, measured at the completed snapshot boundary.

Matched normal controls have 1.37% Head A and 4.35% Head B false-positive rates.
The original held-out normal day has 1.05% and 0.059% respectively. Normal-only
evaluation measures false alarms, not attack recall.

Validation reconstruction MSE is 0.03989 versus training 0.03911 and a mean
predictor baseline of 0.86007. Balanced link validation BCE is 0.01795 versus
training 0.00814. The engineering quality gate passed. These losses do not prove
absence of overfitting or generalization to real devices.

The completed synthetic scan captures modeled their selected ports as closed.
The subsequent real-collector compatibility fix allows scans of provisioned open
lab ports; it does not change this saved checkpoint or retroactively alter its
evaluation. Future matrices must use new directories and document that variation.

The model is a development candidate. Next work should address benign Head B
generalization/calibration, per-service or per-peer timing and longer causal
sequence evidence for beaconing, suitable simple baselines, and an independent
real Mininet attack/control evaluation. Do not fit a better threshold on the
already-inspected test scores and call the resulting metric independent.

Reports and models are preserved in the Windows project under
`data/gnn/local-v2-run/`; raw new scenario captures remain under the same relative
directory in the `automud` distribution. See LOCAL_WSL.md for monitoring and setup.

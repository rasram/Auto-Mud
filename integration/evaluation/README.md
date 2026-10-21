# integration/evaluation/

**Owner:** Rashwanth Ram (evaluation framework). Model-level validation is in `ml/training/` (Jayan).

Current implementation and measured results are documented in the
[shared evaluation guide](../../scripts/integrated_evaluation/README.md) and
[presentation results](../../docs/presentation/AutoMUD_Presentation_Results.md).
The native verification, observation audit and acceptance receipt commands live
in [`integration/live`](../live/README.md). Labelled-record recounts are in
`scripts/integrated_evaluation/`; they require separately supplied evidence.
The dated evaluation protocol, personal progress viewer and source corpus are
private. The shortened study verifies offline layers and separate controller
mechanics; it does not establish same-packet live automatic-response accuracy.

The outline below records earlier evaluation goals, rather than a list of
implemented baselines or completed experiments.

The evaluation framework:

- **Attack scenarios:** port scan, lateral movement, data exfiltration, and C2 beaconing, each injected one at a time (injection lives in `network/attacks/`).
- **Baselines:** Suricata (rule-based), a flow-only ablation with no graph component, and a Wang et al. (2023) replication (transformer, no graph).
- **Metrics:** detection rate, false positive rate, automated response latency (first malicious packet → enforcement), and attack surface reduction compared with Osman et al.'s 65.85%.
- **Poisoned-baseline stress test:** compromise a device during the learning window and measure how well the three defenses limit contamination.

Methodology: Stage 4, steps 15–17. Feeds **Objectives 3–5**.

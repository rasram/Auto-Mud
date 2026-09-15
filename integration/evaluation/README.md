# integration/evaluation/

**Owner:** Rashwanth Ram (evaluation framework). Model-level validation is in `ml/training/` (Jayan).

The evaluation framework:

- **Attack scenarios:** port scan, lateral movement, data exfiltration, and C2 beaconing, each injected one at a time (injection lives in `network/attacks/`).
- **Baselines:** Suricata (rule-based), a flow-only ablation with no graph component, and a Wang et al. (2023) replication (transformer, no graph).
- **Metrics:** detection rate, false positive rate, automated response latency (first malicious packet → enforcement), and attack surface reduction compared with Osman et al.'s 65.85%.
- **Poisoned-baseline stress test:** compromise a device during the learning window and measure how well the three defenses limit contamination.

Methodology: Stage 4, steps 15–17. Feeds **Objectives 3–5**.

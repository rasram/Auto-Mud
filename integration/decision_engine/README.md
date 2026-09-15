# integration/decision_engine/

**Owner:** Rashwanth Ram

When a device's anomaly score is above threshold, the Decision Engine uses simple if-else threshold logic to choose a response tier:

1. Alert only
2. Rate-limit bandwidth
3. VLAN isolate (quarantine)
4. Full block

Each decision goes to both the Ryu controller (`network/sdn/`) and the explanation module (`integration/explanation/`).

This engine is deliberately **not** an LLM generating network rules. That approach was explicitly rejected (§14).

Methodology: Stage 3, steps 12–13.

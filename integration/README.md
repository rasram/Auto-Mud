# integration/ — System Integration & Evaluation

**Owner:** Rashwanth Ram

Connects the stages into the continuous live pipeline, makes response decisions, and runs the system-level evaluation.

| Subdirectory | Contents |
|---|---|
| `orchestrator/` | The 60s live detection loop: Zeek → profiling → graph → GNN → decision |
| `decision_engine/` | Threshold-based response tier selection |
| `explanation/` | LLM-based plain-English alert generation for the homeowner |
| `evaluation/` | Attack scenarios, baselines, metrics, poisoned-baseline stress test |

The web dashboard, also owned by Rashwanth, is in the top-level `dashboard/`.

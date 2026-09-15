# integration/orchestrator/

**Owner:** Rashwanth Ram

Pipeline orchestration for the continuous live detection loop. Every 60s it takes new Zeek flows, calls the frozen profile engine for deviation scores, updates the Neo4j graph, runs the frozen GraphSAGE model, and passes anomaly scores to the Decision Engine.

Methodology: Stage 2, steps 9–11.

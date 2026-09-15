# ml/graph/

**Owner:** Jayan Subramanian

Builds and maintains the device communication graph in Neo4j:

- Nodes are devices.
- Edges are observed communication flows, with byte, protocol, and timing attributes.
- The graph updates every 60 seconds and should reflect real-time topology changes.

Methodology: Stage 2, step 10. Feeds **Objective 2**.

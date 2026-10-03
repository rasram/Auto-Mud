# ml/graph/

**Owner:** Jayan Subramanian

Builds device communication graphs directly from canonical interval telemetry;
Neo4j is not required. See [the schema](../../docs/gnn/SCHEMA.md).

The original persistence proposal described the following behavior:

- Nodes are devices.
- Edges are observed communication flows, with byte, protocol, and timing attributes.
- The graph updates every 60 seconds and should reflect real-time topology changes.

Methodology: Stage 2, step 10. Feeds **Objective 2**.

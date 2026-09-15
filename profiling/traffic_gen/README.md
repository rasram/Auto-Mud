# profiling/traffic_gen/

**Owner:** Sarveshwar Balu

Python traffic-generator scripts, one per virtual device type. They reproduce behavioral patterns taken from the datasets and run continuously as background traffic inside Mininet.

These scripts are *designed from* the datasets. The profile engine and GNN are **not** trained on their output (see "Why This Isn't Circular", §7).

Methodology: Stage 1, step 7.

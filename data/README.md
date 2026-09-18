# data/ — Shared Datasets & Artifacts

**Owner:** Shared (all members)

The directory structure is committed, but large files (PCAPs, CSVs, Zeek logs, model weights, archives) are git-ignored. See `.gitignore`. Each subdirectory's README should note where its data comes from so teammates can reproduce it locally.

| Subdirectory | Contents |
|---|---|
| `raw/` | Original datasets, unmodified |
| `processed/` | Reproducible derived data, including generated testbed traffic, run logs, captures, extracted features, and graph snapshots |
| `artifacts/` | Versioned or separately shared frozen outputs consumed by generators and the live inference loop |

Generated testbed data belongs under `processed/testbed/`, not beside runtime
code in `network/testbed/`. The calibrated statistics used to generate that
traffic live under `artifacts/traffic_generation/` because they are an input
to repeatable runs rather than the output of one run.

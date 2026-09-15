# data/ — Shared Datasets & Artifacts

**Owner:** Shared (all members)

The directory structure is committed, but large files (PCAPs, CSVs, Zeek logs, model weights, archives) are git-ignored. See `.gitignore`. Each subdirectory's README should note where its data comes from so teammates can reproduce it locally.

| Subdirectory | Contents |
|---|---|
| `raw/` | Original datasets, unmodified |
| `processed/` | Extracted features and graph snapshots derived from `raw/` |
| `artifacts/` | Frozen outputs of Stage 0 that the live loop consumes |

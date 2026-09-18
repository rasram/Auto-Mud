# data/processed/

**Owner:** Shared (written mainly by `profiling/features/` and `ml/dataset_prep/`)

Derived data: generated testbed traffic, testbed captures and logs, Zeek flow
logs, per-device feature tables, and labeled graph snapshots. Everything here
should be reproducible from source datasets and versioned artifacts using the
repository's code.

| Subdirectory | Contents |
|---|---|
| `testbed/` | Per-device generated/replay-safe traffic plus outputs from Mininet runs |

Derived data files are intentionally git-ignored. Keep the README files in
version control so the expected local layout and reproduction steps remain
clear.

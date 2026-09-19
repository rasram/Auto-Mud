# data/processed/

**Owner:** Shared (written mainly by `profiling/features/` and `ml/dataset_prep/`)

Derived data: generated testbed traffic, testbed captures and logs, Zeek flow
logs, per-device feature tables, and labeled graph snapshots. Everything here
should be reproducible from source datasets and versioned artifacts using the
repository's code.

| Subdirectory | Contents |
|---|---|
| `testbed/` | Per-device generated/replay-safe traffic plus outputs from Mininet runs |
| `unsw/behavioral_profiles/` | Zeek-derived per-device window baselines for deviation scoring |
| `unsw/reports/` | Zeek profile comparison with MUDgee references |

Large intermediate files are ignored; the frozen Zeek behavioral profiles and
their reference comparison report are tracked.

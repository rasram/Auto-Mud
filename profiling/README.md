# profiling/ — Data & Profiling Engineering

**Owner:** Sarveshwar Balu

Turns Zeek traffic metadata into frozen per-device behavioral profiles and
deviation scores. It also generates background traffic for the testbed.

| Subdirectory | Contents |
|---|---|
| `features/` | Per-device flow feature extraction from Zeek logs |
| `traffic_gen/` | Per-device-type traffic generator scripts for Mininet |
| `profile_engine/` | Behavioral Profiling Engine: baseline construction and deviation scoring |
| `validation/` | Comparison of generated profiles with MUDgee ground truth (Objective 1) |

The maintained path is `features/windows.py` ->
`profile_engine/build_profile.py` -> `profile_engine/score_window.py`.
See [ENGINE_COMPARISON.md](ENGINE_COMPARISON.md) for the implementation decision
and its evaluation limits.

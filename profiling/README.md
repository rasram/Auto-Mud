# profiling/ — Data & Profiling Engineering

**Owner:** Sarveshwar Balu

Turns traffic into per-device behavioral profiles (automatically generated MUD-like profiles) and deviation scores. Also generates realistic background traffic for the testbed.

| Subdirectory | Contents |
|---|---|
| `features/` | Per-device flow feature extraction from Zeek logs |
| `traffic_gen/` | Per-device-type traffic generator scripts for Mininet |
| `profile_engine/` | Behavioral Profiling Engine: baseline construction and deviation scoring |
| `validation/` | Comparison of generated profiles with MUDgee ground truth (Objective 1) |

Note: the "Behavioral Profile Engine" and the "automated MUD profile engine" are the same system (§14).

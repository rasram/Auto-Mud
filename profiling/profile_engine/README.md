# profiling/profile_engine/

**Owner:** Sarveshwar Balu

The Behavioral Profiling Engine.

- **Offline (Stage 0, step 3):** computes robust statistics per device type (median/IQR, 3σ outlier exclusion) and produces a frozen MUD-like JSON profile.
- **Live (Stage 2, step 9):** runs in frozen inference mode and computes a behavioral deviation score per device (new destinations, volume z-score, protocol drift, etc.). It does not relearn.

Also covers the poisoned-baseline defenses (§14): hard constraint rules, cross-validation against clean datasets, and robust statistics.

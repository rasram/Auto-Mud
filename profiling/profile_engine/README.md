# profiling/profile_engine/

**Owner:** Sarveshwar Balu

The Behavioral Profiling Engine.

- **Offline (Stage 0, step 3):** computes robust statistics per device type (median/IQR, 3σ outlier exclusion) and produces a frozen MUD-like JSON profile.
- **Live (Stage 2, step 9):** runs in frozen inference mode and computes a behavioral deviation score per device (new destinations, volume z-score, protocol drift, etc.). It does not relearn.

Also covers the poisoned-baseline defenses (§14): hard constraint rules, cross-validation against clean datasets, and robust statistics.

## Offline profile generation

`generator.py` streams every available device PCAP/PCAPNG with a standard-library
packet reader. It infers the
device MAC from the filename, learns DNS-to-IP mappings and bidirectional
services, and records robust five-minute-window statistics (median, IQR, and a
3-sigma upper bound after Tukey outlier exclusion). It emits RFC 8520-shaped
JSON without reading any ground-truth profile.

Run the complete generation and held-out scoring pipeline from the project root:

    .\.venv\Scripts\python.exe -m profiling.run_unsw_profiling

The command discovers `.pcap` and `.pcapng` files dynamically, so future device captures are
included without code changes. Generated profiles are written to
`data/processed/generated_muds/`. Capture-derived observations are cached in
`temp/profile_cache/`; reference profiles are used only for scoring after
generation. The corpus runner uses two packets for DNS-named services and a
capture-size-aware threshold for unnamed IPs (1% of observed packets, bounded
from 2 to 5,000); both can be overridden with CLI flags.

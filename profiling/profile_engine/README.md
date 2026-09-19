# profiling/profile_engine/

**Owner:** Sarveshwar Balu

The Zeek behavioral profiling engine has two stages:

1. `build_profile.py` combines 60-second windows from
   `../features/windows.py` with observed endpoints from Zeek logs. It writes
   a frozen per-device JSON baseline with robust feature statistics and
   calibration.
2. `score_window.py` compares subsequent windows against that baseline and
   returns a deviation score with component evidence. It does not relearn
   during scoring.

Build all available UNSW profiles and validate their observed endpoints with
the MUDgee reference set from the repository root:

```sh
bash scripts/UNSW-IoTraffic/build_all_profiles.sh
```

The frozen profiles live in `data/processed/unsw/behavioral_profiles/`. The
live orchestrator and response tier selection are unfinished;
`score_window.suggest_tiers()` currently raises `NotImplementedError`.
The committed profiles predate the destination-port and TLS certificate
attribution fixes and need regeneration before revised metrics are reported.

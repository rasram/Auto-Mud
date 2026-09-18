# data/artifacts/traffic_generation/

**Owner:** Shared (produced by the UNSW IoTraffic calibration helpers)

Frozen calibration artifacts used to create repeatable testbed traffic.

- `device_traffic_profiles.json` contains per-device distributions derived
  from UNSW IoTraffic flows. `network/testbed/device_agent.py` and the
  standalone traffic generator use these distributions for cloud
  destinations, ports, protocols, timing, packet counts, and payload sizes.

Regenerate the profile with
`scripts/UNSW-IoTraffic/calibrate_device_traffic_profiles.py`. Its default
output points here.

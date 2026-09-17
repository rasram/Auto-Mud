# network/testbed/

**Owner:** Anand Mahadev

The Mininet + Open vSwitch virtual home network and its device traffic
generation inputs. The current testbed models a household of IoT devices
using traffic calibrated from the UNSW IoTraffic dataset.

## Files

- `device_agent.py` runs one device's traffic agent. It can generate an
	offline JSON event log, emit events in live mode, send packets through Scapy
	on a Mininet interface, or replay a previously generated log.
- `traffic_common.py` contains the shared profile loading, distribution
	sampling, calibrated cloud-traffic generation, and device-to-device edge
	generation used by the agent.
- `device_traffic_profiles.json` stores the per-device traffic statistics
	produced from UNSW IoTraffic calibration. These profiles control cloud
	destinations, ports, protocols, timing, packet counts, and payload sizes.
- `topology.json` defines the device list, stable Mininet IP addresses, and
	deliberately authored household automation edges such as hub-to-bulb and
	motion-sensor-to-camera traffic.

## Workflow

1. Generate or update `device_traffic_profiles.json` with the helpers in
	 `scripts/UNSW-IoTraffic/`.
2. Use `device_agent.py --mode offline` to create inspectable per-device event
	 logs, then merge them with `scripts/UNSW-IoTraffic/merge_offline_logs.py`
	 when a household log is needed.
3. Use `--mode replay` for a fixed event sequence during Mininet evaluation,
	 or use `--mode live` to generate events against the current clock.

The generated logs are intended to feed the Zeek and graph-construction
pipeline. Attack traffic is added separately by the network attack tooling.

Methodology: Stage 1, step 6.

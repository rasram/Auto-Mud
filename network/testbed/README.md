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
- `topology.json` defines the device list, stable Mininet IP addresses, and
	deliberately authored household automation edges such as hub-to-bulb and
	motion-sensor-to-camera traffic.
- `run_full_topology.py` creates the complete Mininet topology, replays each
	device's prepared traffic, captures the network with `tcpdump`, and opens the
	Mininet CLI.

The calibrated generator profile is stored at
`data/artifacts/traffic_generation/device_traffic_profiles.json`. Generated
traffic and run output are data products, so they live under
`data/processed/testbed/` rather than in this runtime-code directory.

## Workflow

1. Generate or update
	 `data/artifacts/traffic_generation/device_traffic_profiles.json` with the
	 calibration helper in `scripts/UNSW-IoTraffic/`.
2. Use `device_agent.py --mode offline` to create inspectable per-device event
	 logs under `data/processed/testbed/generated/`, then create normalized copies
	 under `data/processed/testbed/replay_safe/`. Merge the generated logs with
	 `scripts/UNSW-IoTraffic/merge_offline_logs.py` when a household log is
	 needed.
3. From the repository root, run `sudo python
	 network/testbed/run_full_topology.py`. By default it replays
	 `data/processed/testbed/replay_safe/` and writes the PCAP and agent logs to
	 `data/processed/testbed/runs/full_topology/`.

The launcher accepts `--topology`, `--traffic-dir`, and `--output-dir` for
non-default layouts. Its defaults are resolved from the repository, so it does
not depend on the caller's working directory.

The generated logs are intended to feed the Zeek and graph-construction
pipeline. Attack traffic is added separately by the network attack tooling.

Methodology: Stage 1, step 6.

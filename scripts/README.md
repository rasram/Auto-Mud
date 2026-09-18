# scripts/

**Owner:** Shared

Cross-cutting helper scripts for preparing and validating the UNSW IoTraffic
dataset, bootstrapping the testbed's traffic inputs, and inspecting shared
outputs. Module-specific runtime code belongs inside its owning module's
directory.

## PCAP topology visualizer

`pcap_topology_visualizer.py` animates packets from a PCAP over the device
layout in `network/testbed/topology.json`. Known device IPs appear as topology
nodes and external endpoints are grouped behind the gateway while retaining
their real addresses in the packet table.

From the repository root:

```bash
python scripts/pcap_topology_visualizer.py \
  data/processed/testbed/runs/full_topology/full-topology.pcap
```

The topology path defaults to `network/testbed/topology.json`; use
`--topology`, `--speed`, or `--max-packets` to override the relevant behavior.
The GUI requires Tkinter and packet decoding requires Scapy.

## `UNSW-IoTraffic/`

- `calibrate_device_traffic_profiles.py` reads per-device UNSW-style flow CSVs
	and writes the numeric, categorical, destination, port, and active-hours
	statistics consumed by `network/testbed/device_agent.py`. Its default output
	is `data/artifacts/traffic_generation/device_traffic_profiles.json`.
- `check_active_hours.py` plots daily hour-of-day activity and flags likely
	truncated or incomplete captures before calibration.
- `merge_offline_logs.py` combines per-device offline JSON event logs into one
	chronologically sorted household log for downstream Zeek and graph
	processing.
- `traffic_generator.py` is the standalone household traffic generator. It
	uses calibrated device statistics plus authored device-to-device automation
	edges to produce a merged event log.

The normal flow is to inspect capture quality, calibrate the device profiles,
generate device or household traffic, and pass the resulting logs to the
testbed and downstream processing pipeline. Generated results should be kept
under `data/processed/testbed/`, outside this helper directory.

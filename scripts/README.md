# scripts/

**Owner:** Shared

Cross-cutting helper scripts for preparing and validating the UNSW IoTraffic
dataset and for bootstrapping the testbed's traffic inputs. Module-specific
runtime code belongs inside its owning module's directory.

## `UNSW-IoTraffic/`

- `calibrate_device_traffic_profiles.py` reads per-device UNSW-style flow CSVs
	and writes the numeric, categorical, destination, port, and active-hours
	statistics consumed by `network/testbed/device_agent.py`.
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
outside this helper directory.

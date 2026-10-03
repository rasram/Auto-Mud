"""Derive generator distributions from canonical normal telemetry, in seconds.

Packet deltas are merged by UID before sampling flow volumes. Scheduling uses
new-flow timestamps, never per-packet interarrival means from vendor CSVs.
"""
from collections import Counter, defaultdict
import random

from ml.schema import VERSION, read_json, read_jsonl, write_json, resolve_device, validate_manifest, validate_telemetry, require, file_hash


def calibrate_traffic(sources, out, maximum_samples=4096):
    profiles = {}
    for source in sources:
        manifest = validate_manifest(read_json(source["manifest"]), training=True)
        require(manifest["normal"], "Generator calibration must use normal captures")
        selected = set(source.get("device_ids", [d["device_id"] for d in manifest["inventory"]]))
        require(selected and selected <= {d["device_id"] for d in manifest["inventory"]}, "Unknown calibration device_ids")
        flows = defaultdict(dict)
        for r in read_jsonl(source["telemetry"]):
            validate_telemetry(r)
            if not manifest["start"] <= r["window_start"] < manifest["end"]:
                continue
            device = resolve_device(manifest, r["orig_h"], r.get("orig_mac"), r["window_start"])
            if device not in selected or r["proto"] not in ("tcp", "udp") or not r.get("resp_p"):
                continue
            if any(o["start"] < r["window_start"] + 60 and o["end"] > r["window_start"]
                   and o.get("device_id", device) == device for o in manifest.get("outages", [])):
                continue
            f = flows[device].setdefault(r["uid"], {"start": r["flow_start"], "duration": 0,
                "tx": 0, "rx": 0, "tx_packets": 0, "rx_packets": 0, "proto": r["proto"], "port": r["resp_p"], "peer": r["resp_h"]})
            f["duration"] = max(f["duration"], r["observed_duration"])
            for field, name in (("tx", "orig_ip_bytes"), ("rx", "resp_ip_bytes"), ("tx_packets", "orig_pkts"), ("rx_packets", "resp_pkts")):
                f[field] += r[name]
        require(selected <= set(flows), "Some selected calibration devices have no initiated TCP/UDP traffic")
        for d, values in flows.items():
            require(d not in profiles, "Declare one merged capture source per calibration device")
            values = sorted(values.values(), key=lambda f: f["start"])
            require(len(values) >= 20, f"Too few initiated normal TCP/UDP flows for {d}")
            gaps = [b["start"] - a["start"] for a, b in zip(values, values[1:]) if b["start"] > a["start"]
                    and not any(o["start"] < b["start"] and o["end"] > a["start"]
                                and o.get("device_id", d) == d for o in manifest.get("outages", []))]
            require(gaps, f"No positive inter-flow gaps for {d}")
            # Account for non-contiguous captures: long observation gaps are not traffic schedules.
            gaps = [min(g, 3600) for g in gaps]
            services = Counter((f["proto"], f["port"]) for f in values)
            hours = Counter(int(f["start"] % 86400 // 3600) for f in values)
            rng = random.Random(42)
            def sample(xs):
                return rng.sample(xs, min(len(xs), maximum_samples))
            # On-wire bytes include headers/retransmits. This is a generator calibration
            # approximation, explicitly bounded and verified again on the actual capture.
            profiles[d] = {"flow_gap_seconds": sample(gaps),
                "duration_seconds": sample([min(10, max(0.01, f["duration"])) for f in values]),
                "request_bytes": sample([min(65536, max(1, f["tx"] - f["tx_packets"] * (40 if f["proto"] == "tcp" else 28))) for f in values]),
                "response_bytes": sample([min(65536, max(0, f["rx"] - f["rx_packets"] * (40 if f["proto"] == "tcp" else 28))) for f in values]),
                "hour_weights": [max(0.05, hours[h] / max(hours.values())) for h in range(24)],
                "services": [{"proto": proto, "port": port, "weight": count / len(values)} for (proto, port), count in services.items() if 0 < port <= 65535],
                "destination_slots": min(16, len({f["peer"] for f in values})),
                "source_run_id": manifest["run_id"], "observed_flows": len(values),
                "source_manifest_sha256": file_hash(source["manifest"]),
                "source_telemetry_sha256": file_hash(source["telemetry"])}
    result = {"schema_version": "automud.generator.v1", "telemetry_version": VERSION, "devices": profiles,
              "approximations": ["Payload sizes approximate IP bytes minus minimum headers", "16 cloud destination slots",
                                 "Durations bounded to 10 seconds; volumes to 64 KiB per event", "Inter-flow gaps capped at 1 hour"]}
    write_json(out, result)
    return result

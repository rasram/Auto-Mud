"""
traffic_common.py

Shared traffic-generation logic used by device_agent.py (the per-device
script each Mininet host runs) and any offline bootstrap tooling. Nothing
in this module knows about "the household" as a whole -- it only knows
how to generate one device's own traffic, given that device's calibrated
profile and (optionally) a list of automation edges where it's the source.
"""

import json
import math
import random
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_profiles(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_topology(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def edges_for_device(topology: dict, device: str) -> list:
    """Edges where `device` is the source -- the only ones this device
    needs to know about to generate its own outgoing automation traffic."""
    return [e for e in topology.get("edges", []) if e["source"] == device]


# ---------------------------------------------------------------------------
# Distribution helpers (robust to heavy-tailed calibration stats)
# ---------------------------------------------------------------------------

def lognormal_params_from_median_iqr(median, q1, q3):
    if median is None or median <= 0:
        return None

    mu = math.log(median)
    z = 0.6745
    sigmas = []
    if q3 is not None and q3 > median:
        sigmas.append(math.log(q3 / median) / z)
    if q1 is not None and 0 < q1 < median:
        sigmas.append(math.log(median / q1) / z)

    sigma = sum(sigmas) / len(sigmas) if sigmas else 0.5
    sigma = max(sigma, 1e-3)
    return mu, sigma


def sample_lognormal(median, q1, q3, fallback=0.0, cap_percentile_z=3.0):
    params = lognormal_params_from_median_iqr(median, q1, q3)
    if params is None:
        return fallback

    mu, sigma = params
    z = random.gauss(0, 1)
    z = max(min(z, cap_percentile_z), -cap_percentile_z)
    return math.exp(mu + sigma * z)


def sample_categorical(distribution: dict, exclude_keys=None):
    if not distribution:
        return None
    items = [(k, v) for k, v in distribution.items() if not exclude_keys or k not in exclude_keys]
    if not items:
        return None
    keys, weights = zip(*items)
    total = sum(weights)
    weights = [w / total for w in weights]
    return random.choices(keys, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Per-device profile wrapper (calibrated cloud traffic)
# ---------------------------------------------------------------------------

class DeviceProfile:
    def __init__(self, name: str, stats: dict, local_ip: str):
        self.name = name
        self.local_ip = local_ip
        self.stats = stats
        self.numeric = stats.get("numeric_stats", {})
        self.categorical = stats.get("categorical_stats", {})
        self.top_dst_ports = stats.get("top_dst_ports", {})
        self.top_destinations = stats.get("top_destinations", {})
        self.new_dest_fraction = stats.get("approx_new_destination_fraction", 0.0)
        self.active_hours_hist = {
            int(h): p for h, p in stats.get("active_hours_histogram", {}).items()
        }

    def hourly_weight(self, hour: int) -> float:
        hist = self.active_hours_hist
        if not hist:
            return 1.0
        max_val = max(hist.values()) or 1.0
        return hist.get(hour, 0.0) / max_val

    def sample_next_interarrival(self) -> float:
        n = self.numeric.get("avgInterarrivalTime", {})
        return max(
            sample_lognormal(n.get("median"), n.get("q1"), n.get("q3"), fallback=60.0),
            0.05,
        )

    def sample_duration(self) -> float:
        n = self.numeric.get("flowDuration", {})
        return max(sample_lognormal(n.get("median"), n.get("q1"), n.get("q3"), fallback=1.0), 0.01)

    def sample_destination(self) -> str:
        """Cloud destination only -- device-to-device edges are handled
        separately, not through this path."""
        if random.random() < self.new_dest_fraction:
            return f"NEW_DEST_{random.randint(1, 254)}"
        return sample_categorical(self.top_destinations) or "UNKNOWN_DEST"

    def sample_port_protocol(self):
        proto = sample_categorical(self.categorical.get("protocol", {})) or "none"
        port = sample_categorical(self.top_dst_ports, exclude_keys={"*"})
        port = int(port) if port and port.isdigit() else None
        ip_proto = sample_categorical(self.categorical.get("ipProto", {}))
        return proto, port, ip_proto

    def sample_packet_counts(self):
        src_n = self.numeric.get("srcNumPackets", {})
        dst_n = self.numeric.get("dstNumPackets", {})
        src_packets = round(sample_lognormal(src_n.get("median"), src_n.get("q1"), src_n.get("q3"), fallback=1.0))
        dst_packets = round(sample_lognormal(dst_n.get("median"), dst_n.get("q1"), dst_n.get("q3"), fallback=1.0))
        return max(src_packets, 1), max(dst_packets, 0)

    def sample_payload_sizes(self):
        src_p = self.numeric.get("srcAvgPayloadSize", {})
        dst_p = self.numeric.get("dstAvgPayloadSize", {})
        src_avg = sample_lognormal(src_p.get("median"), src_p.get("q1"), src_p.get("q3"), fallback=64.0)
        dst_avg = sample_lognormal(dst_p.get("median"), dst_p.get("q1"), dst_p.get("q3"), fallback=64.0)
        return src_avg, dst_avg

    def generate_cloud_flow(self, timestamp: datetime) -> dict:
        protocol, port, ip_proto = self.sample_port_protocol()
        src_packets, dst_packets = self.sample_packet_counts()
        src_avg_payload, dst_avg_payload = self.sample_payload_sizes()

        return {
            "flow_type": "cloud",
            "device": self.name,
            "src_ip": self.local_ip,
            "timestamp": timestamp.isoformat(),
            "destination": self.sample_destination(),
            "dst_port": port,
            "ip_proto": ip_proto,
            "protocol": protocol,
            "duration_sec": round(self.sample_duration(), 3),
            "src_num_packets": src_packets,
            "dst_num_packets": dst_packets,
            "src_avg_payload_bytes": round(src_avg_payload, 1),
            "dst_avg_payload_bytes": round(dst_avg_payload, 1),
        }


def simulate_device_cloud_traffic(profile: DeviceProfile, start_time: datetime, hours: float):
    """Yields this device's own calibrated cloud-traffic flows across the window."""
    t = start_time
    end_time = start_time + timedelta(hours=hours)

    while t < end_time:
        weight = max(profile.hourly_weight(t.hour), 0.05)
        gap = profile.sample_next_interarrival() / weight
        t = t + timedelta(seconds=gap)
        if t >= end_time:
            break
        yield profile.generate_cloud_flow(t), gap


# ---------------------------------------------------------------------------
# Household automation edges (device-to-device, not calibration-derived)
# ---------------------------------------------------------------------------

def simulate_device_edges(device_edges: list, device_ip_map: dict, start_time: datetime, hours: float):
    """Yields device-to-device flow events for edges where the current
    device is the source, using a simple Poisson-style trigger process
    independent of the device's own calibrated cloud-traffic timing."""
    end_time = start_time + timedelta(hours=hours)

    for edge in device_edges:
        if edge["dest"] not in device_ip_map:
            continue  # skip edges pointing at a device not in this topology

        rate_per_sec = edge["avg_events_per_hour"] / 3600.0
        t = start_time
        while t < end_time:
            gap = random.expovariate(rate_per_sec) if rate_per_sec > 0 else float("inf")
            t = t + timedelta(seconds=gap)
            if t >= end_time:
                break

            low, high = edge["payload_bytes_range"]
            payload = random.uniform(low, high)

            yield {
                "flow_type": "household_edge",
                "device": edge["source"],
                "src_ip": device_ip_map[edge["source"]],
                "timestamp": t.isoformat(),
                "destination": device_ip_map[edge["dest"]],
                "dst_port": edge["port"],
                "ip_proto": "6",
                "protocol": edge["protocol"],
                "duration_sec": round(random.uniform(0.05, 0.5), 3),
                "src_num_packets": random.randint(1, 3),
                "dst_num_packets": random.randint(1, 3),
                "src_avg_payload_bytes": round(payload, 1),
                "dst_avg_payload_bytes": round(payload * 0.3, 1),
                "edge_description": edge["description"],
            }, gap

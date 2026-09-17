"""
traffic_generator.py

Simulates a full household of devices on one shared clock, using the
calibration statistics from device_profiles.json for each device's own
cloud traffic, plus a small set of deliberately-authored device-to-device
"automation" edges (motion sensor -> bulb, hub -> plug, etc.) that the
calibration data cannot supply on its own (real IoT traffic is
overwhelmingly device-to-cloud).

Output is ONE merged, chronologically-sorted event log across the whole
household -- this is what feeds your Zeek/Neo4j graph-construction step,
not 12 independent per-device files.

Usage:
    python traffic_generator.py --profiles device_profiles.json \
        --hours 24 --out household_traffic.json

Wiring generated flows into actual Mininet host traffic (via scapy) is a
separate, later step -- see send_flow_via_scapy at the bottom.
"""

import argparse
import json
import math
import random
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# CONFIG -- edit this table to change which devices are simulated, their
# assigned local IPs, and the device-to-device automation edges. Everything
# below this block adapts automatically.
# ---------------------------------------------------------------------------

DEVICE_SUBSET = [
    "SamsungSmartThings_d052a800675e_flows",      # hub
    "AmazonEcho_44650d56ccd3_flows",              # voice assistant
    "PhilipsHue_0017882b9a25_flows",              # bulb
    "BelkinWemoSwitch_ec1a5979f489_flows",        # smart plug
    "SamsungCamera_00166cab6b88_flows",           # camera (high volume)
    "NestDropCam_308cfb2fe4b2_flows",             # camera (low volume)
    "AugustDoorBell_e076d03f00ae_flows",          # doorbell
    "BelkinWemoMotionSensor_ec1a59832811_flows",  # motion sensor
    "HPPrinter_705a0fe49bc0_flows",               # printer
    "NetatmoWeatherStation_70ee5003b8ac_flows",   # environmental sensor
    "AwairAirQuality_70886b100fc6_flows",         # environmental sensor
    "WithingsSmartScale_0024e41b6f96_flows",      # health device (very quiet)
]

# Assign each device a stable local IP -- these are the node identities
# your Neo4j graph and device-to-device edges will reference.
DEVICE_LOCAL_IP = {
    key: f"10.0.0.{11 + i}" for i, key in enumerate(DEVICE_SUBSET)
}

# Device-to-device automation edges: these are hand-authored, NOT derived
# from calibration data, since UNSW traffic has essentially no genuine
# device-to-device signal. avg_events_per_hour is a rough, editable
# assumption -- tune based on how "active" you want household automation
# to look relative to each device's cloud traffic volume.
HOUSEHOLD_EDGES = [
    {
        "source": "AmazonEcho_44650d56ccd3_flows",
        "dest": "SamsungSmartThings_d052a800675e_flows",
        "avg_events_per_hour": 6,
        "port": 8080, "protocol": "http", "payload_bytes_range": (60, 200),
        "description": "voice command routed to hub",
    },
    {
        "source": "SamsungSmartThings_d052a800675e_flows",
        "dest": "PhilipsHue_0017882b9a25_flows",
        "avg_events_per_hour": 10,
        "port": 80, "protocol": "http", "payload_bytes_range": (40, 150),
        "description": "hub-issued bulb command",
    },
    {
        "source": "SamsungSmartThings_d052a800675e_flows",
        "dest": "BelkinWemoSwitch_ec1a5979f489_flows",
        "avg_events_per_hour": 4,
        "port": 80, "protocol": "http", "payload_bytes_range": (40, 150),
        "description": "hub-issued plug command",
    },
    {
        "source": "BelkinWemoMotionSensor_ec1a59832811_flows",
        "dest": "PhilipsHue_0017882b9a25_flows",
        "avg_events_per_hour": 12,
        "port": 80, "protocol": "http", "payload_bytes_range": (40, 120),
        "description": "motion-triggered lighting",
    },
    {
        "source": "BelkinWemoMotionSensor_ec1a59832811_flows",
        "dest": "SamsungCamera_00166cab6b88_flows",
        "avg_events_per_hour": 3,
        "port": 554, "protocol": "rtsp", "payload_bytes_range": (100, 300),
        "description": "motion-triggered recording",
    },
    {
        "source": "AugustDoorBell_e076d03f00ae_flows",
        "dest": "SamsungSmartThings_d052a800675e_flows",
        "avg_events_per_hour": 2,
        "port": 8080, "protocol": "http", "payload_bytes_range": (60, 200),
        "description": "doorbell event notification to hub",
    },
]


# ---------------------------------------------------------------------------
# Distribution helpers (unchanged from before -- robust to heavy-tailed stats)
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
        separately by simulate_household_edges, not through this path."""
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
        yield profile.generate_cloud_flow(t)


# ---------------------------------------------------------------------------
# Household automation edges (device-to-device, not calibration-derived)
# ---------------------------------------------------------------------------

def simulate_household_edges(edges, device_ip_map, start_time: datetime, hours: float):
    """Yields device-to-device flow events for each configured automation
    edge, using a simple Poisson-style trigger process independent of
    each device's own calibrated cloud-traffic timing."""
    end_time = start_time + timedelta(hours=hours)

    for edge in edges:
        if edge["source"] not in device_ip_map or edge["dest"] not in device_ip_map:
            continue  # skip edges referencing a device not in DEVICE_SUBSET

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
                "ip_proto": "6",  # TCP by default for these local automation flows
                "protocol": edge["protocol"],
                "duration_sec": round(random.uniform(0.05, 0.5), 3),
                "src_num_packets": random.randint(1, 3),
                "dst_num_packets": random.randint(1, 3),
                "src_avg_payload_bytes": round(payload, 1),
                "dst_avg_payload_bytes": round(payload * 0.3, 1),
                "edge_description": edge["description"],
            }


# ---------------------------------------------------------------------------
# Household-wide simulation
# ---------------------------------------------------------------------------

def simulate_household(profiles_path: str, device_subset: list, edges: list, hours: float):
    with open(profiles_path) as f:
        all_profiles = json.load(f)

    missing = [d for d in device_subset if d not in all_profiles]
    if missing:
        raise SystemExit(f"These devices are not in {profiles_path}: {missing}")

    device_objs = {
        key: DeviceProfile(key, all_profiles[key], DEVICE_LOCAL_IP[key])
        for key in device_subset
    }

    start_time = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)

    all_flows = []
    for key, profile in device_objs.items():
        flows = list(simulate_device_cloud_traffic(profile, start_time, hours))
        all_flows.extend(flows)
        print(f"  {key}: {len(flows)} cloud flows generated")

    edge_flows = list(simulate_household_edges(edges, DEVICE_LOCAL_IP, start_time, hours))
    all_flows.extend(edge_flows)
    print(f"  household automation edges: {len(edge_flows)} flows generated across {len(edges)} edge(s)")

    all_flows.sort(key=lambda f: f["timestamp"])
    return all_flows


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Simulate a full household's traffic from calibration profiles.")
    parser.add_argument("--profiles", required=True, help="Path to device_profiles.json")
    parser.add_argument("--hours", type=float, default=24.0, help="Hours of traffic to simulate")
    parser.add_argument("--out", default="household_traffic.json", help="Output file for the merged event log")
    args = parser.parse_args()

    print(f"Simulating household of {len(DEVICE_SUBSET)} devices for {args.hours}h...")
    flows = simulate_household(args.profiles, DEVICE_SUBSET, HOUSEHOLD_EDGES, args.hours)

    with open(args.out, "w") as f:
        json.dump(flows, f, indent=2)

    print(f"\nTotal: {len(flows)} flows -> {args.out}")


# ---------------------------------------------------------------------------
# Stub: wiring a generated flow into an actual Mininet host via scapy.
# Needs real interface context from the Mininet testbed -- left here as a
# starting point for integration with Anand's setup.
# ---------------------------------------------------------------------------

def send_flow_via_scapy(flow: dict, iface: str):
    from scapy.all import IP, TCP, UDP, ICMP, send

    proto_map = {"6": TCP, "17": UDP}
    layer_cls = proto_map.get(str(flow.get("ip_proto")), None)

    pkt = IP(src=flow["src_ip"], dst=flow["destination"])
    if layer_cls is TCP and flow.get("dst_port"):
        pkt = pkt / TCP(dport=flow["dst_port"])
    elif layer_cls is UDP and flow.get("dst_port"):
        pkt = pkt / UDP(dport=flow["dst_port"])
    else:
        pkt = pkt / ICMP()

    payload_size = int(flow.get("src_avg_payload_bytes", 0))
    if payload_size > 0:
        pkt = pkt / ("X" * payload_size)

    for _ in range(flow.get("src_num_packets", 1)):
        send(pkt, iface=iface, verbose=False)


if __name__ == "__main__":
    main()
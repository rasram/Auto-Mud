"""
device_agent.py

Generic per-device traffic agent. Anand's Mininet setup launches ONE
instance of this per host, each pointed at a different --device. Each
instance only knows about its own calibrated profile and the automation
edges where it is the SOURCE (looked up from the shared topology.json) --
it never needs to know about any other device's internals.

Two modes:
  offline  -- generate this device's traffic for --hours and dump to a
              JSON file (used for bootstrapping training data before
              Mininet exists, or for testing/inspection).
  live     -- run against a real clock (optionally accelerated via
              --speed) and either print each event or, if --iface is
              given, actually send it as a packet via scapy.

Usage:
    # Offline: generate 24h of this device's traffic to a file
    python device_agent.py --device AmazonEcho_44650d56ccd3_flows \
        --profiles device_profiles.json --topology topology.json \
        --mode offline --hours 24 --out echo_traffic.json

    # Live, inside a Mininet host, accelerated 10x, sending real packets
    python device_agent.py --device AmazonEcho_44650d56ccd3_flows \
        --profiles device_profiles.json --topology topology.json \
        --mode live --hours 24 --speed 10 --iface eth0
"""

import argparse
import json
import time
from datetime import datetime, timezone

from traffic_common import (
    DeviceProfile,
    load_profiles,
    load_topology,
    edges_for_device,
    simulate_device_cloud_traffic,
    simulate_device_edges,
)


def send_flow_via_scapy(flow: dict, iface: str):
    """Turn one generated flow record into actual packets on this host's
    interface. Only called in --mode live with --iface set."""
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


def run_offline(profile: DeviceProfile, device_edges: list, device_ip_map: dict, hours: float, out_path: str):
    start_time = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)

    flows = [f for f, _gap in simulate_device_cloud_traffic(profile, start_time, hours)]
    edge_flows = [f for f, _gap in simulate_device_edges(device_edges, device_ip_map, start_time, hours)]

    all_flows = sorted(flows + edge_flows, key=lambda f: f["timestamp"])

    with open(out_path, "w") as f:
        json.dump(all_flows, f, indent=2)

    print(f"[{profile.name}] offline: {len(flows)} cloud flows + {len(edge_flows)} edge flows -> {out_path}")


def run_live(profile: DeviceProfile, device_edges: list, device_ip_map: dict,
             hours: float, speed: float, iface: str):
    """
    Merges this device's own cloud-traffic generator and its outgoing
    edge generator into one real-time (or accelerated) event loop.
    `speed` > 1 compresses time -- e.g. speed=10 replays a 24h learning
    phase in 2.4h of wall-clock time, matching the accelerated-clock
    approach discussed for compressing the calibration learning phase.
    """
    start_time = datetime.now(timezone.utc)

    cloud_gen = simulate_device_cloud_traffic(profile, start_time, hours)
    edge_gen = simulate_device_edges(device_edges, device_ip_map, start_time, hours)

    def next_or_none(gen):
        try:
            return next(gen)
        except StopIteration:
            return None

    next_cloud = next_or_none(cloud_gen)
    next_edge = next_or_none(edge_gen)
    count = 0

    while next_cloud is not None or next_edge is not None:
        # pick whichever event is scheduled sooner
        if next_edge is None or (next_cloud is not None and next_cloud[0]["timestamp"] <= next_edge[0]["timestamp"]):
            flow, gap = next_cloud
            next_cloud = next_or_none(cloud_gen)
        else:
            flow, gap = next_edge
            next_edge = next_or_none(edge_gen)

        time.sleep(max(gap, 0) / speed)

        if iface:
            send_flow_via_scapy(flow, iface)
        else:
            print(json.dumps(flow))

        count += 1

    print(f"[{profile.name}] live run complete: {count} events sent", flush=True)


def run_replay(input_path: str, speed: float, iface: str):
    """
    Deterministically replays a previously-generated offline traffic file
    (from --mode offline) in timestamp order. No profile/topology lookups
    needed here -- the file already contains everything (src_ip,
    destination, ports, sizes). This is the mode you actually want for
    real Mininet runs and for fair evaluation comparisons: the traffic is
    fixed and inspectable ahead of time, and attacks can be spliced into
    the file directly before replay.
    """
    with open(input_path) as f:
        flows = json.load(f)

    flows.sort(key=lambda f: f["timestamp"])

    prev_ts = None
    count = 0
    for flow in flows:
        ts = datetime.fromisoformat(flow["timestamp"])
        if prev_ts is not None:
            gap = (ts - prev_ts).total_seconds()
            time.sleep(max(gap, 0) / speed)
        prev_ts = ts

        if iface:
            send_flow_via_scapy(flow, iface)
        else:
            print(json.dumps(flow))

        count += 1

    print(f"[replay: {input_path}] complete: {count} events sent", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Per-device traffic agent -- run one instance per Mininet host.")
    parser.add_argument("--device", help="Device key, must match both profiles and topology. Required for offline/live modes.")
    parser.add_argument("--profiles", help="Path to device_profiles.json. Required for offline/live modes.")
    parser.add_argument("--topology", help="Path to topology.json. Required for offline/live modes.")
    parser.add_argument("--mode", choices=["offline", "live", "replay"], default="offline")
    parser.add_argument("--hours", type=float, default=24.0)
    parser.add_argument("--out", default=None, help="Offline mode: output JSON path (default: <device>_traffic.json)")
    parser.add_argument("--input", default=None, help="Replay mode: path to a previously-generated offline JSON file.")
    parser.add_argument("--speed", type=float, default=1.0, help="Live/replay mode: time-compression factor (10 = 10x faster than real time)")
    parser.add_argument("--iface", default=None, help="Live/replay mode: network interface to send packets on. Omit to just print events.")
    args = parser.parse_args()

    if args.mode == "replay":
        if not args.input:
            raise SystemExit("--mode replay requires --input <file>")
        run_replay(args.input, args.speed, args.iface)
        return

    if not (args.device and args.profiles and args.topology):
        raise SystemExit("--mode offline/live require --device, --profiles, and --topology")

    all_profiles = load_profiles(args.profiles)
    topology = load_topology(args.topology)

    if args.device not in all_profiles:
        raise SystemExit(f"Device '{args.device}' not found in {args.profiles}")
    if args.device not in topology.get("device_ip", {}):
        raise SystemExit(f"Device '{args.device}' not found in {args.topology}'s device_ip map")

    local_ip = topology["device_ip"][args.device]
    profile = DeviceProfile(args.device, all_profiles[args.device], local_ip)
    device_edges = edges_for_device(topology, args.device)

    if args.mode == "offline":
        out_path = args.out or f"{args.device}_traffic.json"
        run_offline(profile, device_edges, topology["device_ip"], args.hours, out_path)
    else:
        run_live(profile, device_edges, topology["device_ip"], args.hours, args.speed, args.iface)


if __name__ == "__main__":
    main()

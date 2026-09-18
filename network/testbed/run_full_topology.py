#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from pathlib import Path

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSBridge


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]


def main():
    parser = argparse.ArgumentParser(
        description="Run the complete Mininet topology with deterministic traffic replay."
    )
    parser.add_argument(
        "--topology",
        type=Path,
        default=SCRIPT_DIR / "topology.json",
        help="Topology definition (default: network/testbed/topology.json)",
    )
    parser.add_argument(
        "--traffic-dir",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "testbed" / "replay_safe",
        help="Directory containing per-device replay JSON files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "testbed" / "runs" / "full_topology",
        help="Directory for the PCAP and per-agent logs",
    )
    parser.add_argument("--speed", type=float, default=3600)
    parser.add_argument("--no-nat", action="store_true")
    args = parser.parse_args()

    topology_path = args.topology.expanduser().resolve()
    traffic_dir = args.traffic_dir.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    agent_path = SCRIPT_DIR / "device_agent.py"
    logs_dir = output_dir / "logs"
    pcap_path = output_dir / "full-topology.pcap"

    logs_dir.mkdir(parents=True, exist_ok=True)

    with topology_path.open() as handle:
        topology = json.load(handle)

    devices = topology["devices"]
    device_ips = topology["device_ip"]

    entries = []
    missing = []

    for index, device in enumerate(devices, start=1):
        short_name = device.split("_", 1)[0]
        traffic_file = traffic_dir / f"{short_name}_traffic.json"

        if not traffic_file.is_file():
            missing.append(str(traffic_file))

        entries.append({
            "host_name": f"h{index}",
            "device": device,
            "short_name": short_name,
            "ip": device_ips[device],
            "traffic_file": traffic_file,
        })

    if not agent_path.is_file():
        raise SystemExit(f"Missing {agent_path}")

    if missing:
        print("Missing traffic files:")
        for path in missing:
            print(f"  {path}")
        raise SystemExit(1)

    net = Mininet(
        controller=None,
        switch=OVSBridge,
        build=False,
        autoSetMacs=True,
        ipBase="10.0.0.0/24",
    )

    switch = net.addSwitch("s1", failMode="standalone")
    hosts = {}

    for entry in entries:
        host = net.addHost(
            entry["host_name"],
            ip=f'{entry["ip"]}/24',
            defaultRoute=None if args.no_nat else "via 10.0.0.254",
        )
        net.addLink(host, switch)
        hosts[entry["device"]] = host

    if not args.no_nat:
        net.addNAT(
            "nat0",
            ip="10.0.0.254/24",
            connect=switch,
        )

    processes = []
    log_handles = []
    capture_process = None
    capture_error_handle = None

    try:
        net.build()
        net.start()

        print("\nDevice mapping:")
        print("-" * 100)
        for entry in entries:
            print(
                f'{entry["host_name"]:4} '
                f'{entry["ip"]:15} '
                f'{entry["short_name"]:28} '
                f'{entry["traffic_file"].name}'
            )
        print("-" * 100)

        print("\nTesting Mininet connectivity...")
        net.pingAll()

        print(f"\nStarting capture: {pcap_path}")
        capture_error_handle = (logs_dir / "tcpdump.log").open("w")

        capture_process = subprocess.Popen(
            [
                "tcpdump",
                "-U",
                "-n",
                "-i",
                "any",
                "net",
                "10.0.0.0/24",
                "-w",
                str(pcap_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=capture_error_handle,
        )

        print(f"Starting {len(entries)} traffic agents at {args.speed}x speed...")

        for entry in entries:
            host = hosts[entry["device"]]
            interface = f'{entry["host_name"]}-eth0'
            log_path = logs_dir / f'{entry["short_name"]}.log'
            log_handle = log_path.open("w")
            log_handles.append(log_handle)

            process = host.popen(
                [
                    sys.executable,
                    "-u",
                    str(agent_path),
                    "--mode",
                    "replay",
                    "--input",
                    str(entry["traffic_file"]),
                    "--speed",
                    str(args.speed),
                    "--iface",
                    interface,
                ],
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )

            processes.append((entry, process))
            print(
                f'  {entry["host_name"]}: '
                f'{entry["short_name"]} '
                f'PID={process.pid} log={log_path}'
            )

        print("\nUseful Mininet CLI commands:")
        print("  nodes")
        print("  links")
        print("  pingall")
        print("  sh ps -eo pid,etime,stat,cmd | grep '[d]evice_agent.py'")
        print("  sh tail -n 5 logs/*.log")
        print("\nWait until no device_agent.py processes remain, then enter: exit\n")

        CLI(net)

    finally:
        print("*** Stopping traffic agents")
        for _, process in processes:
            if process.poll() is None:
                process.terminate()

        for _, process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

        if capture_process is not None:
            capture_process.terminate()
            try:
                capture_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                capture_process.kill()

        for handle in log_handles:
            handle.close()

        if capture_error_handle is not None:
            capture_error_handle.close()

        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()

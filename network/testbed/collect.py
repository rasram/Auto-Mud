"""Unattended, isolated Mininet run with a dedicated OVS sensor mirror.

Run as root on Linux. No NAT, public destinations, or Ryu enforcement is enabled.
"""
import argparse
import json
import math
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

from ml.schema import VERSION, file_hash, read_json, write_json, write_jsonl, require
from network.testbed.collection_plan import inventory, label_intervals, build_plan


def collect(plan_path, out, smoke=False):
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    plan_path, out = Path(plan_path).resolve(), Path(out).resolve()
    plan = read_json(plan_path)
    require(plan.get("schema_version") == "automud.collection.v1", "Unknown collection plan")
    require(plan["calibrated"] or smoke, "Uncalibrated traffic is only permitted with --smoke")
    require(not out.exists(), "Use a new output directory; captures must not be overwritten")
    existing = subprocess.run(["ovs-vsctl", "br-exists", "s1"], capture_output=True)
    require(existing.returncode != 0, "An s1 bridge already exists; stop the previous testbed first")
    out.mkdir(parents=True)
    logs = out / "logs"
    logs.mkdir()
    net = Mininet(controller=None, switch=OVSBridge, build=False, ipBase="10.0.0.0/24")
    switch = net.addSwitch("s1", failMode="standalone")
    topology = plan["topology"]
    hosts = {}
    for i, d in enumerate(topology["devices"], 1):
        h = net.addHost(f"h{i}", ip=topology["device_ip"][d] + "/24", mac=f"02:00:00:00:00:{i:02x}")
        net.addLink(h, switch)
        hosts[d] = h
    cloud = net.addHost("cloud", ip=plan["cloud_ips"][0] + "/24", mac="02:00:00:00:01:00")
    net.addLink(cloud, switch)
    sensor = net.addHost("sensor", ip=None)
    sensor_link = net.addLink(sensor, switch)
    server_processes, agents, handles = [], [], []
    capture, manifest = None, None
    completed = False
    transport = Path(__file__).with_name("socket_traffic.py").resolve()
    try:
        net.build()
        net.start()
        for h in [*hosts.values(), cloud, sensor]:
            # Avoid checksum/segmentation offload artifacts in recorded training data.
            result = h.cmd(f"ethtool -K {h.defaultIntf()} tx off rx off tso off gso off gro off 2>&1")
            (logs / f"{h.name}-offload.log").write_text(result)
        for ip in plan["cloud_ips"][1:]:
            cloud.cmd(f"ip addr add {ip}/24 dev {cloud.defaultIntf()}")
        mirror_port = sensor_link.intf2.name
        subprocess.run(["ovs-vsctl", "--", "--id=@p", "get", "Port", mirror_port,
            "--", "--id=@m", "create", "Mirror", "name=automud", "select-all=true", "output-port=@p",
            "--", "set", "Bridge", "s1", "mirrors=@m"], check=True, capture_output=True)
        for h in [*hosts.values(), cloud]:
            log_path = logs / f"{h.name}-server.log"
            handle = log_path.open("w")
            handles.append(handle)
            p = h.popen([sys.executable, "-u", str(transport), "serve", "--plan", str(plan_path)], stdout=handle, stderr=subprocess.STDOUT)
            server_processes.append(p)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(all(p.poll() is None for p in server_processes), "Responder startup failed; inspect server logs")
            if all('"ready": true' in (logs / f"{h.name}-server.log").read_text() for h in [*hosts.values(), cloud]):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Responder readiness timed out")
        cap_handle = (logs / "tcpdump.log").open("w")
        handles.append(cap_handle)
        capture = sensor.popen(["tcpdump", "-U", "-n", "-s", "0", "-B", "4096", "-i", str(sensor.defaultIntf()),
                                "-w", str(out / "capture.pcap")], stdout=subprocess.DEVNULL, stderr=cap_handle)
        time.sleep(1)
        require(capture.poll() is None, "tcpdump did not start")
        start = int(math.ceil((time.time() + 90) / 60) * 60)
        profiles = None
        if plan.get("profiles_file"):
            require(file_hash(plan["profiles_file"]) == plan["profiles_sha256"], "Calibration profile changed after plan generation")
            profiles = read_json(plan["profiles_file"])
        require(profiles is not None or smoke, "Calibrated collection requires a referenced profile file")
        # Reconstruct with the same seed against the actual common UTC phase.
        # This prevents a noon start from replaying the midnight activity weights.
        plan = {**plan, **build_plan(topology, plan["duration"], plan["seed"], profiles,
            plan["scenario"], plan["actor"], plan["onset"], plan["normal_control"], start % 86400)}
        executed_plan = out / "executed-plan.json"
        write_json(executed_plan, plan)
        require(time.time() < start - 5, "Plan generation missed its common start; rerun after reducing load")
        end = start + plan["duration"]
        manifest = {"schema_version": VERSION, "run_id": plan["run_id"], "session_id": plan["session_id"],
            "source": "mininet", "start": start, "end": end, "normal": not plan["scenario"] or plan["normal_control"],
            "capture_complete": False, "replay_speed": 1, "inventory": inventory(topology, start, end),
            "seed": plan["seed"], "plan_sha256": file_hash(plan_path), "calibrated_generator": plan["calibrated"],
            "executed_plan_sha256": file_hash(executed_plan),
            "smoke": smoke, "capture_drops": None, "clock": "UTC", "capture_point": "s1 dedicated OVS mirror"}
        write_json(out / "manifest.json", manifest)
        write_jsonl(out / "labels.jsonl", label_intervals(plan, start))
        for d, h in hosts.items():
            handle = (logs / f"{h.name}-agent.log").open("w")
            handles.append(handle)
            p = h.popen([sys.executable, "-u", str(transport), "replay", "--plan", str(executed_plan), "--device", d,
                        "--start", str(start)], stdout=handle, stderr=subprocess.STDOUT)
            agents.append(p)
        while time.time() < end + 20:
            require(capture.poll() is None and all(p.poll() is None for p in server_processes), "Capture/responder stopped early")
            require(all(p.poll() in (None, 0) for p in agents), "Traffic agent failed or missed deadlines; inspect logs")
            if time.time() >= end and all(p.poll() == 0 for p in agents):
                completed = True
                break
            time.sleep(0.5)
    finally:
        for p in agents + server_processes:
            if p.poll() is None:
                p.terminate()
        for p in agents + server_processes:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if capture is not None:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=10)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait()
                completed = False
        for h in handles:
            h.close()
        net.stop()
        if manifest:
            text = (logs / "tcpdump.log").read_text()
            match = re.search(r"(\d+) packets dropped by kernel", text)
            drops = int(match.group(1)) if match else None
            manifest.update(capture_drops=drops, capture_complete=bool(completed and drops == 0),
                            pcap_sha256=file_hash(out / "capture.pcap") if (out / "capture.pcap").exists() else None)
            write_json(out / "manifest.json", manifest)
    require(manifest and manifest["capture_complete"], "Run did not complete cleanly; manifest is marked incomplete")
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--smoke", action="store_true")
    args = p.parse_args()
    collect(args.plan, args.out, args.smoke)


if __name__ == "__main__":
    main()

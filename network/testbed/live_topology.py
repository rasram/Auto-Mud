"""Controller-managed Saturn testbed with a dedicated mirrored Zeek sensor."""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import re
from pathlib import Path
from urllib.request import Request, urlopen

from integration.live.common import atomic_json, canonical_digest
from integration.live.config import interval_inventory, load_deployment


def _mininet():
    try:
        from mininet.cli import CLI
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
    except ModuleNotFoundError:
        sys.path.append("/usr/lib/python3/dist-packages")
        from mininet.cli import CLI
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
    return CLI, setLogLevel, Mininet, OVSSwitch, RemoteController


def _controller_ready(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _clock_synchronized():
    result = subprocess.run(
        ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
        capture_output=True, text=True, check=False,
    )
    return result.returncode == 0 and result.stdout.strip().lower() == "yes"


def _api(url, path, value=None):
    data = json.dumps(value).encode() if value is not None else None
    request = Request(url.rstrip("/") + path, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def _packet_loss(output):
    match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    if not match:
        raise RuntimeError("Could not parse ping result: " + output)
    return float(match.group(1))


def action_smoke(deployment, hosts, bridge, run_id, run_root):
    source, target, unaffected = deployment["devices"][:3]
    source_host = hosts[source["device_id"]]
    unaffected_host = hosts[unaffected["device_id"]]
    before = source_host.cmd(f"ping -c 2 -W 1 {target['ip']}")
    if _packet_loss(before) != 0:
        raise RuntimeError("Action target was unreachable before qualification")
    decision_id = canonical_digest([run_id, "scoped-action-smoke"])
    request = {
        "schema_version": "automud.action-request.v1", "decision_id": decision_id,
        "proposal_id": canonical_digest([decision_id, "proposal"]),
        "evidence_id": canonical_digest([decision_id, "engineering-evidence"]),
        "observation_kind": "engineering", "inventory_version": deployment["inventory_version"],
        "window_end": int(time.time()),
        "dpid": deployment["network"]["dpid"], "device_id": source["device_id"],
        "device_mac": source["mac"], "device_ip": source["ip"], "switch_port": source["switch_port"],
        "action": "block", "scope": {"proto": "icmp", "destination_ip": target["ip"], "destination_port": None},
        "priority": 40000, "ttl_seconds": 5, "reason": "explicit_engineering_scope_and_expiry_test",
    }
    accepted = _api(deployment["network"]["controller_api"], "/v1/actions", request)
    retry = _api(deployment["network"]["controller_api"], "/v1/actions", request)
    deadline = time.monotonic() + 5
    status = accepted
    while status["status"] != "installed" and time.monotonic() < deadline:
        time.sleep(0.1)
        status = _api(deployment["network"]["controller_api"], "/v1/actions/" + decision_id)
    if status["status"] != "installed" or retry["cookie"] != accepted["cookie"]:
        raise RuntimeError("Controller did not confirm idempotent rule installation")
    flows_installed = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge], capture_output=True, text=True, check=True,
    ).stdout
    blocked = source_host.cmd(f"ping -c 2 -W 1 {target['ip']}")
    unaffected_output = unaffected_host.cmd(f"ping -c 2 -W 1 {target['ip']}")
    if _packet_loss(blocked) != 100 or _packet_loss(unaffected_output) != 0:
        raise RuntimeError("Scoped action did not have the intended isolated traffic effect")
    time.sleep(max(0, status["expires_at"] - time.time() + 1))
    expired = _api(deployment["network"]["controller_api"], "/v1/actions/" + decision_id)
    recovered = source_host.cmd(f"ping -c 2 -W 1 {target['ip']}")
    if expired["status"] != "expired" or _packet_loss(recovered) != 0:
        raise RuntimeError("Temporary action did not expire with connectivity recovery")
    report = {
        "schema_version": "automud.controller-action-smoke.v1", "status": "passed",
        "request": request, "accepted": accepted, "idempotent_retry": retry,
        "installed": status, "expired": expired,
        "target_loss_before_percent": _packet_loss(before),
        "target_loss_during_percent": _packet_loss(blocked),
        "unaffected_loss_during_percent": _packet_loss(unaffected_output),
        "target_loss_after_percent": _packet_loss(recovered),
        "installed_flow_dump": flows_installed,
    }
    atomic_json(run_root / "controller-action-smoke.json", report)
    return report


def run(config_path, duration=0, no_cli=False, run_action_smoke=False):
    if os.geteuid() != 0:
        raise RuntimeError("Run the live topology with sudo /usr/bin/python3")
    CLI, set_log_level, Mininet, OVSSwitch, RemoteController = _mininet()
    set_log_level("info")
    deployment = load_deployment(config_path)
    network = deployment["network"]
    if not _controller_ready(network["controller_host"], int(network["controller_port"])):
        raise RuntimeError("Controller is not listening at the configured address")
    bridge = network["bridge"]
    if subprocess.run(["ovs-vsctl", "br-exists", bridge], capture_output=True).returncode == 0:
        raise RuntimeError(f"Bridge {bridge} already exists; stop the earlier lab first")
    runtime_root = Path(deployment["paths"]["runtime_root"])
    run_id = "saturn-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_root = runtime_root / "runs" / run_id
    zeek_dir = run_root / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=False)
    net = Mininet(controller=None, switch=OVSSwitch, build=False, ipBase=network["subnet"], autoSetMacs=False)
    controller = net.addController(
        "c0", controller=RemoteController, ip=network["controller_host"], port=int(network["controller_port"]),
    )
    switch = net.addSwitch(
        bridge, dpid=network["dpid"], protocols=network["openflow"], failMode=network["fail_mode"],
    )
    hosts = {}
    for index, device in enumerate(deployment["devices"], 1):
        host = net.addHost(f"h{index}", ip=device["ip"] + "/24", mac=device["mac"])
        net.addLink(host, switch)
        hosts[device["device_id"]] = host
    sensor = net.addHost(network["sensor_name"], ip=None)
    sensor_link = net.addLink(sensor, switch)
    zeek_process = None
    started = int(time.time())
    try:
        net.build()
        controller.start()
        switch.start([controller])
        for host in [*hosts.values(), sensor]:
            result = host.cmd(f"ethtool -K {host.defaultIntf()} tx off rx off tso off gso off gro off 2>&1")
            (run_root / f"{host.name}-offload.log").write_text(result)
        sensor_port = sensor_link.intf2.name
        subprocess.run([
            "ovs-vsctl", "--", "--id=@p", "get", "Port", sensor_port,
            "--", "--id=@m", "create", "Mirror", "name=automud", "select-all=true", "output-port=@p",
            "--", "set", "Bridge", bridge, "mirrors=@m",
        ], check=True, capture_output=True)
        wrapper = run_root / "automud-live.zeek"
        synchronized = "T" if _clock_synchronized() else "F"
        wrapper.write_text(
            f'@load {deployment["paths"]["zeek_policy"]}\n'
            f'redef AutoMUD::clock_synchronized = {synchronized};\n'
        )
        zeek_log = (run_root / "zeek.stderr.log").open("w")
        zeek_process = sensor.popen([
            deployment["paths"]["zeek"], "-i", network["sensor_interface"], str(wrapper),
        ], cwd=str(zeek_dir), stdout=zeek_log, stderr=subprocess.STDOUT)
        time.sleep(2)
        if zeek_process.poll() is not None:
            raise RuntimeError("Zeek failed to start; inspect zeek.stderr.log")
        health_path = zeek_dir / "automud-health.log"
        runtime = {
            "schema_version": "automud.live-runtime.v1", "run_id": run_id,
            "session_id": run_id, "started_at": started,
            "deployment_id": deployment["deployment_id"], "inventory_version": deployment["inventory_version"],
            "dpid": network["dpid"], "controller": f"{network['controller_host']}:{network['controller_port']}",
            "bridge": bridge, "sensor_interface": network["sensor_interface"], "sensor_switch_port": sensor_port,
            "inventory": interval_inventory(deployment, started),
            "telemetry_log": str(zeek_dir / "automud-window.log"), "health_log": str(health_path),
        }
        atomic_json(run_root / "runtime.json", runtime)
        atomic_json(runtime_root / "current.json", runtime)
        print(json.dumps(runtime, indent=2), flush=True)
        print("*** Controller connectivity and baseline ping", flush=True)
        # The passive sensor intentionally has no IP address and must not be
        # included in the device connectivity matrix.
        loss = net.ping(list(hosts.values()))
        if loss:
            raise RuntimeError(f"Baseline connectivity lost {loss}% of packets")
        if run_action_smoke:
            report = action_smoke(deployment, hosts, bridge, run_id, run_root)
            print(json.dumps({"controller_action_smoke": report["status"]}), flush=True)
        if duration > 0:
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                if zeek_process.poll() is not None:
                    raise RuntimeError("Zeek stopped during the run")
                time.sleep(0.5)
        elif not no_cli:
            CLI(net)
        return runtime
    finally:
        if zeek_process and zeek_process.poll() is None:
            zeek_process.send_signal(signal.SIGINT)
            try:
                zeek_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                zeek_process.kill()
                zeek_process.wait()
        net.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--no-cli", action="store_true")
    parser.add_argument("--action-smoke", action="store_true")
    args = parser.parse_args()
    run(args.config, duration=args.duration, no_cli=args.no_cli, run_action_smoke=args.action_smoke)


if __name__ == "__main__":
    main()

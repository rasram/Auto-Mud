"""Controller-managed Saturn testbed with a dedicated mirrored Zeek sensor."""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
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


def _process_identity():
    stat = Path(f"/proc/{os.getpid()}/stat").read_text().split()
    return {
        "topology_pid": os.getpid(),
        "topology_process_start_ticks": int(stat[21]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def _api(url, path, value=None, method=None):
    data = json.dumps(value).encode() if value is not None else None
    request = Request(
        url.rstrip("/") + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def _tcp_reachable(host, address, port):
    output = host.cmd(
        "python3 -c 'import socket; "
        f"s=socket.create_connection((\"{address}\",{int(port)}),2); "
        "s.close(); print(\"AUTOMUD_OK\")' 2>&1"
    )
    return "AUTOMUD_OK" in output


def _wait_action(api, decision_id, wanted, timeout=5):
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        status = _api(api, "/v1/actions/" + decision_id)
        if status.get("status") in wanted:
            return status
        time.sleep(0.1)
    raise RuntimeError(f"Controller action {decision_id} did not reach {sorted(wanted)}: {status}")


def action_smoke(deployment, hosts, bridge, run_id, run_root, run_controller_outage=False):
    source, target, unaffected = deployment["devices"][:3]
    source_host = hosts[source["device_id"]]
    target_host = hosts[target["device_id"]]
    unaffected_host = hosts[unaffected["device_id"]]
    port = 18080
    server = target_host.popen(["python3", "-m", "http.server", str(port), "--bind", target["ip"]])
    try:
        time.sleep(0.5)
        before = _tcp_reachable(source_host, target["ip"], port)
        if not before:
            raise RuntimeError("Action target TCP service was unreachable before qualification")

        def request_for(label, ttl):
            decision_id = canonical_digest([run_id, label])
            return {
                "schema_version": "automud.action-request.v1", "decision_id": decision_id,
                "proposal_id": canonical_digest([decision_id, "proposal"]),
                "evidence_id": canonical_digest([decision_id, "engineering-evidence"]),
                "observation_kind": "engineering", "inventory_version": deployment["inventory_version"],
                "window_end": int(time.time()),
                "dpid": deployment["network"]["dpid"], "device_id": source["device_id"],
                "device_mac": source["mac"], "device_ip": source["ip"], "switch_port": source["switch_port"],
                "action": "block",
                "scope": {"proto": "tcp", "destination_ip": target["ip"], "destination_port": port},
                "priority": 40000, "ttl_seconds": ttl,
                "reason": "explicit_engineering_scope_and_lifecycle_test",
            }

        request = request_for("scoped-action-expiry-smoke", 5)
        accepted = _api(deployment["network"]["controller_api"], "/v1/actions", request)
        retry = _api(deployment["network"]["controller_api"], "/v1/actions", request)
        installed = _wait_action(
            deployment["network"]["controller_api"], request["decision_id"], {"installed"},
        )
        if retry["cookie"] != accepted["cookie"]:
            raise RuntimeError("Controller did not preserve the idempotent action cookie")
        flows_installed = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge],
            capture_output=True, text=True, check=True,
        ).stdout
        blocked = _tcp_reachable(source_host, target["ip"], port)
        unaffected_reachable = _tcp_reachable(unaffected_host, target["ip"], port)
        if blocked or not unaffected_reachable:
            raise RuntimeError("Scoped action did not have the intended isolated TCP effect")
        time.sleep(max(0, installed["expires_at"] - time.time() + 1))
        expired = _wait_action(
            deployment["network"]["controller_api"], request["decision_id"], {"expired"},
        )
        recovered = _tcp_reachable(source_host, target["ip"], port)
        if not recovered:
            raise RuntimeError("Temporary action did not recover after hard expiry")

        revoke_request = request_for("scoped-action-revoke-smoke", 30)
        _api(deployment["network"]["controller_api"], "/v1/actions", revoke_request)
        revoke_installed = _wait_action(
            deployment["network"]["controller_api"], revoke_request["decision_id"], {"installed"},
        )
        if _tcp_reachable(source_host, target["ip"], port):
            raise RuntimeError("Revocation test action did not block its target")
        _api(
            deployment["network"]["controller_api"],
            "/v1/actions/" + revoke_request["decision_id"], method="DELETE",
        )
        revoked = _wait_action(
            deployment["network"]["controller_api"], revoke_request["decision_id"], {"removed"},
        )
        revoke_recovered = _tcp_reachable(source_host, target["ip"], port)
        if not revoke_recovered:
            raise RuntimeError("Connectivity did not recover after explicit revoke")
        outage = None
        if run_controller_outage:
            outage_request = request_for("controller-outage-expiry-smoke", 5)
            _api(deployment["network"]["controller_api"], "/v1/actions", outage_request)
            outage_installed = _wait_action(
                deployment["network"]["controller_api"], outage_request["decision_id"], {"installed"},
            )
            if _tcp_reachable(source_host, target["ip"], port):
                raise RuntimeError("Outage test action did not block its target")
            subprocess.run(["systemctl", "stop", "automud-controller"], check=True)
            try:
                blocked_without_controller = not _tcp_reachable(source_host, target["ip"], port)
                time.sleep(max(0, outage_installed["expires_at"] - time.time() + 1))
                recovered_without_controller = _tcp_reachable(source_host, target["ip"], port)
            finally:
                subprocess.run(["systemctl", "start", "automud-controller"], check=True)
            deadline = time.monotonic() + 10
            while True:
                try:
                    restarted_actions = _api(deployment["network"]["controller_api"], "/v1/actions")
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Controller API did not recover after outage")
                    time.sleep(0.2)
            if not blocked_without_controller or not recovered_without_controller:
                raise RuntimeError("Switch did not preserve TTL isolation and autonomous recovery")
            outage = {
                "request": outage_request, "installed": outage_installed,
                "blocked_while_controller_down": blocked_without_controller,
                "recovered_while_controller_down": recovered_without_controller,
                "controller_actions_after_restart": restarted_actions.get("actions", []),
            }
        report = {
            "schema_version": "automud.controller-action-smoke.v2", "status": "passed",
            "request": request, "accepted": accepted, "idempotent_retry": retry,
            "installed": installed, "expired": expired,
            "tcp_reachable_before": before, "tcp_reachable_during": blocked,
            "unaffected_tcp_reachable_during": unaffected_reachable,
            "tcp_reachable_after_expiry": recovered,
            "revoke_request": revoke_request, "revoke_installed": revoke_installed,
            "revoked": revoked, "tcp_reachable_after_revoke": revoke_recovered,
            "controller_outage": outage,
            "installed_flow_dump": flows_installed,
        }
        atomic_json(run_root / "controller-action-smoke.json", report)
        return report
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def run(
    config_path, duration=0, no_cli=False, run_action_smoke=False,
    sensor_interruption_after=None, force_clock_unsynchronized=False,
    run_controller_outage=False,
):
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
    runtime = None
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
        synchronized = "T" if _clock_synchronized() and not force_clock_unsynchronized else "F"
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
            "active": True, **_process_identity(),
            "deployment_id": deployment["deployment_id"], "inventory_version": deployment["inventory_version"],
            "dpid": network["dpid"], "controller": f"{network['controller_host']}:{network['controller_port']}",
            "bridge": bridge, "sensor_interface": network["sensor_interface"], "sensor_switch_port": sensor_port,
            "inventory": interval_inventory(deployment, started),
            "telemetry_log": str(zeek_dir / "automud-window.log"), "health_log": str(health_path),
            "dns_log": str(zeek_dir / "dns.log"),
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
            report = action_smoke(
                deployment, hosts, bridge, run_id, run_root,
                run_controller_outage=run_controller_outage,
            )
            print(json.dumps({"controller_action_smoke": report["status"]}), flush=True)
        if duration > 0:
            run_started = time.monotonic()
            deadline = time.monotonic() + duration
            sensor_interrupted = False
            while time.monotonic() < deadline:
                if (
                    sensor_interruption_after is not None and not sensor_interrupted
                    and time.monotonic() - run_started >= sensor_interruption_after
                ):
                    zeek_process.send_signal(signal.SIGINT)
                    zeek_process.wait(timeout=10)
                    sensor_interrupted = True
                    runtime["sensor_interruption_at"] = int(time.time())
                    atomic_json(run_root / "runtime.json", runtime)
                    atomic_json(runtime_root / "current.json", runtime)
                if zeek_process.poll() is not None and not sensor_interrupted:
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
        if runtime is not None:
            runtime["active"] = False
            runtime["stopped_at"] = int(time.time())
            atomic_json(run_root / "runtime.json", runtime)
            atomic_json(runtime_root / "current.json", runtime)
        net.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--no-cli", action="store_true")
    parser.add_argument("--action-smoke", action="store_true")
    parser.add_argument("--controller-outage-smoke", action="store_true")
    parser.add_argument("--sensor-interruption-after", type=float)
    parser.add_argument("--force-clock-unsynchronized", action="store_true")
    args = parser.parse_args()
    run(
        args.config, duration=args.duration, no_cli=args.no_cli,
        run_action_smoke=args.action_smoke,
        run_controller_outage=args.controller_outage_smoke,
        sensor_interruption_after=args.sensor_interruption_after,
        force_clock_unsynchronized=args.force_clock_unsynchronized,
    )


if __name__ == "__main__":
    main()

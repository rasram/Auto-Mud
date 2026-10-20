"""Low-rate isolated lab probes; never training data or accuracy evidence."""
import argparse
import json
import select
import signal
import socket
import time


def probe_plan(deployment):
    """Exercise the existing six local permissions and one denied ring per host."""
    if deployment["observation_kind"] != "engineering" or deployment["decision"]["mode"] != "observe":
        raise ValueError("Lab probes require engineering / observe")
    devices = deployment["devices"]
    by_id = {row["device_id"]: row for row in devices}
    with open(deployment["mud"]["policy"], encoding="utf-8") as handle:
        policy = json.load(handle)
    plans = {row["device_id"]: [] for row in devices}
    for rule in policy.get("permissions", []):
        if rule.get("proto") == "tcp" and rule.get("initiator") in by_id and rule.get("responder") in by_id:
            plans[rule["initiator"]].append([by_id[rule["responder"]]["ip"], rule["service_port"]])
    for index, row in enumerate(devices):
        plans[row["device_id"]].append([devices[(index + 1) % len(devices)]["ip"], 18080])
    return plans


def run(address, ports, targets, interval=10):
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    listeners = []
    try:
        for port in ports:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port))
            listener.listen(32)
            listener.setblocking(False)
            listeners.append(listener)
        next_probe = time.monotonic() + 3
        while running:
            ready, _, _ = select.select(listeners, [], [], .2)
            for listener in ready:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(.5)
                    try:
                        connection.recv(256)
                        connection.sendall(b"AutoMUD engineering probe\n")
                    except OSError:
                        pass
            if time.monotonic() >= next_probe:
                for target, port in targets:
                    try:
                        with socket.create_connection((target, port), timeout=.5) as connection:
                            connection.sendall(b"AutoMUD engineering probe\n")
                    except OSError:
                        pass
                next_probe = time.monotonic() + interval
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument("--ports", required=True)
    parser.add_argument("--targets", required=True)
    args = parser.parse_args()
    run(args.address, json.loads(args.ports), json.loads(args.targets))

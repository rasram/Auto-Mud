import ipaddress
from pathlib import Path

from integration.live.common import read_json, resolve_project_path


def load_deployment(path):
    path = Path(path).resolve()
    value = read_json(path)
    if value.get("schema_version") != "automud.deployment.v1":
        raise ValueError("Unsupported deployment configuration")
    devices = value.get("devices", [])
    if not devices:
        raise ValueError("Deployment inventory is empty")
    for field in ("device_id", "ip", "mac"):
        entries = [str(device[field]).lower() if field == "mac" else str(device[field]) for device in devices]
        if len(entries) != len(set(entries)):
            raise ValueError(f"Duplicate inventory {field}")
    subnet = ipaddress.ip_network(value["network"]["subnet"])
    for index, device in enumerate(devices, 1):
        device.setdefault("switch_port", index)
        if ipaddress.ip_address(device["ip"]) not in subnet:
            raise ValueError(f"Device outside deployment subnet: {device['device_id']}")
    ports = [int(device["switch_port"]) for device in devices]
    if len(ports) != len(set(ports)):
        raise ValueError("Duplicate inventory switch_port")
    value["_path"] = str(path)
    value["_policy_path"] = str(resolve_project_path(value["mud"]["policy"]))
    return value


def interval_inventory(deployment, start, end=None):
    return [
        {
            "device_id": device["device_id"],
            "device_type": device["device_type"],
            "mac": device["mac"].lower(),
            "addresses": [{"ip": device["ip"], "start": int(start), "end": end}],
        }
        for device in deployment["devices"]
    ]


def bindings(deployment):
    by_ip = {device["ip"]: device for device in deployment["devices"]}
    by_id = {device["device_id"]: device for device in deployment["devices"]}
    return by_ip, by_id

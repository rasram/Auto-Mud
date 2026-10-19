import ipaddress
from pathlib import Path

from integration.live.common import read_json, resolve_project_path


def load_deployment(path):
    path = Path(path).resolve()
    value = read_json(path)
    version = value.get("schema_version")
    if version not in ("automud.deployment.v1", "automud.deployment.v2"):
        raise ValueError("Unsupported deployment configuration")
    devices = value.get("devices", [])
    if not devices:
        raise ValueError("Deployment inventory is empty")
    subnet = ipaddress.ip_network(value["network"]["subnet"])
    ids = [str(device["device_id"]) for device in devices]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate inventory device_id")
    if version == "automud.deployment.v1":
        _validate_v1(devices, subnet)
    else:
        _validate_v2(devices, subnet)
    value["_path"] = str(path)
    value["_policy_path"] = str(resolve_project_path(value["mud"]["policy"]))
    return value


def interval_inventory(deployment, start, end=None):
    start = int(start)
    end = int(end) if end is not None else None
    if deployment["schema_version"] == "automud.deployment.v1":
        return [
            {
                "device_id": device["device_id"],
                "device_type": device["device_type"],
                "mac": device["mac"].lower(),
                "addresses": [{"ip": device["ip"], "start": start, "end": end}],
            }
            for device in deployment["devices"]
        ]
    result = []
    window_end = end if end is not None else float("inf")
    for device in deployment["devices"]:
        active = [
            binding for binding in device["bindings"]
            if binding["valid_from"] < window_end
            and (binding.get("valid_until") is None or binding["valid_until"] > start)
        ]
        addresses = [{
            "ip": binding["ip"],
            "start": binding["valid_from"],
            "end": binding.get("valid_until"),
        } for binding in active]
        macs = {binding["mac"] for binding in active}
        row = {
            "device_id": device["device_id"],
            "device_type": device["device_type"],
            "addresses": sorted(addresses, key=lambda item: (item["ip"], item["start"])),
        }
        if len(macs) == 1:
            row["mac"] = next(iter(macs))
        result.append(row)
    return result


def bindings(deployment, at=None):
    if deployment["schema_version"] == "automud.deployment.v1":
        selected = deployment["devices"]
    else:
        if at is None:
            raise ValueError("A UTC timestamp is required for deployment v2 bindings")
        selected = []
        for device in deployment["devices"]:
            binding = active_binding(deployment, device["device_id"], at)
            if binding is not None:
                selected.append({
                    "device_id": device["device_id"],
                    "device_type": device["device_type"],
                    **binding,
                })
    by_ip = {device["ip"]: device for device in selected}
    by_id = {device["device_id"]: device for device in selected}
    return by_ip, by_id


def active_binding(deployment, device_id, at):
    """Return the one binding active at a UTC instant, or None when unavailable."""
    at = int(at)
    for device in deployment["devices"]:
        if device["device_id"] != device_id:
            continue
        if deployment["schema_version"] == "automud.deployment.v1":
            return {
                "ip": device["ip"], "mac": device["mac"].lower(),
                "switch_port": int(device["switch_port"]),
                "valid_from": 0, "valid_until": None,
            }
        matches = [
            binding for binding in device["bindings"]
            if binding["valid_from"] <= at
            and (binding.get("valid_until") is None or at < binding["valid_until"])
        ]
        if len(matches) > 1:
            raise ValueError(f"Ambiguous active binding for {device_id}")
        return dict(matches[0]) if matches else None
    return None


def _validate_v1(devices, subnet):
    for field in ("ip", "mac"):
        entries = [str(device[field]).lower() if field == "mac" else str(device[field]) for device in devices]
        if len(entries) != len(set(entries)):
            raise ValueError(f"Duplicate inventory {field}")
    for index, device in enumerate(devices, 1):
        device.setdefault("switch_port", index)
        device["switch_port"] = int(device["switch_port"])
        device["mac"] = str(device["mac"]).lower()
        device["ip"] = str(ipaddress.ip_address(device["ip"]))
        if ipaddress.ip_address(device["ip"]) not in subnet:
            raise ValueError(f"Device outside deployment subnet: {device['device_id']}")
    ports = [device["switch_port"] for device in devices]
    if len(ports) != len(set(ports)):
        raise ValueError("Duplicate inventory switch_port")


def _overlap(left, right):
    left_end = left.get("valid_until")
    right_end = right.get("valid_until")
    return (left_end is None or right["valid_from"] < left_end) and (
        right_end is None or left["valid_from"] < right_end
    )


def _validate_v2(devices, subnet):
    all_bindings = []
    for device in devices:
        raw = device.get("bindings") or []
        if not raw:
            raise ValueError(f"Device has no bindings: {device['device_id']}")
        normalized = []
        for binding in raw:
            item = dict(binding)
            item["ip"] = str(ipaddress.ip_address(item["ip"]))
            item["mac"] = str(item["mac"]).lower()
            item["switch_port"] = int(item["switch_port"])
            item["valid_from"] = int(item["valid_from"])
            if item.get("valid_until") is not None:
                item["valid_until"] = int(item["valid_until"])
                if item["valid_until"] <= item["valid_from"]:
                    raise ValueError(f"Invalid binding interval: {device['device_id']}")
            if ipaddress.ip_address(item["ip"]) not in subnet:
                raise ValueError(f"Device outside deployment subnet: {device['device_id']}")
            if item["switch_port"] <= 0:
                raise ValueError(f"Invalid switch port: {device['device_id']}")
            normalized.append(item)
            all_bindings.append((device["device_id"], item))
        normalized.sort(key=lambda item: item["valid_from"])
        for left, right in zip(normalized, normalized[1:]):
            if _overlap(left, right):
                raise ValueError(f"Overlapping bindings for {device['device_id']}")
        device["bindings"] = normalized
    for index, (left_id, left) in enumerate(all_bindings):
        for right_id, right in all_bindings[index + 1:]:
            if left_id == right_id or not _overlap(left, right):
                continue
            conflicts = [
                name for name in ("ip", "mac", "switch_port")
                if left[name] == right[name]
            ]
            if conflicts:
                raise ValueError(
                    f"Conflicting live binding ({', '.join(conflicts)}): {left_id} and {right_id}"
                )

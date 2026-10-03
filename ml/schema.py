"""The ordered, versioned public contracts. No ML dependencies required."""
import hashlib
import ipaddress
import json
import math
from pathlib import Path

VERSION = "automud.graph.v1"
WINDOW = 60
FEATURES = (
    "tx_ip_bytes", "rx_ip_bytes", "tx_packets", "rx_packets", "active_flows",
    "initiated_flows", "inbound_flows", "unique_destinations",
    "new_destination_fraction", "unique_destination_ports", "destination_port_entropy",
    "tcp_fraction", "udp_fraction", "icmp_fraction", "tcp_failed_fraction",
    "mean_observed_flow_duration", "median_observed_flow_duration", "log_tx_rx_ratio",
)
TYPES = ("hub", "speaker", "light", "plug", "camera", "doorbell", "motion_sensor",
         "printer", "environmental_sensor", "scale", "unknown")
LOG_FEATURES = tuple(i for i in range(18) if i in (*range(8), 9, 15, 16))
HISTORY_FEATURE = FEATURES.index("new_destination_fraction")
X_NAMES = FEATURES + ("time_sin", "time_cos", "active") + tuple("type_" + t for t in TYPES) + tuple("valid_" + f for f in FEATURES)
MASK_OFFSET = len(FEATURES) + 3 + len(TYPES)
SCHEMA_HASH = hashlib.sha256(json.dumps({"version": VERSION, "features": X_NAMES,
    "window": WINDOW, "log_features": LOG_FEATURES}, sort_keys=True).encode()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def read_jsonl(path):
    with Path(path).open(encoding="utf-8-sig") as handle:
        for n, line in enumerate(handle, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except ValueError as exc:
                    raise ValueError(f"{path}:{n}: invalid JSON") from exc


def write_jsonl(path, values):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, allow_nan=False) + "\n")


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_manifest(m, training=False):
    require(m.get("schema_version") == VERSION, "Wrong manifest schema_version")
    for key in ("run_id", "source", "session_id", "inventory", "start", "end", "normal", "capture_complete", "replay_speed"):
        require(key in m, f"Manifest missing {key}")
    require(m["end"] > m["start"], "Capture end must follow start")
    require(m["start"] % WINDOW == 0 and m["end"] % WINDOW == 0, "Capture bounds must be UTC minute boundaries")
    require(isinstance(m["normal"], bool) and isinstance(m["capture_complete"], bool), "normal/capture_complete must be booleans")
    require(len(m["inventory"]) > 0, "Empty inventory")
    ids = [d["device_id"] for d in m["inventory"]]
    require(len(ids) == len(set(ids)), "Duplicate device identities")
    for d in m["inventory"]:
        require(d.get("device_type") in TYPES, f"Unknown type: {d.get('device_type')}")
        require(d.get("mac") or d.get("addresses"), f"Missing identity mapping for {d['device_id']}")
        for a in d.get("addresses", []):
            ipaddress.ip_address(a["ip"])
            require(a.get("end", m["end"]) > a.get("start", m["start"]), "Invalid address lease")
    if training:
        require(m["capture_complete"], "Incomplete capture is not training data")
        require(m["replay_speed"] == 1, "Accelerated replay is not training data")
        require(m.get("capture_drops", 0) == 0, "Capture drops: repair collection before training")
        if m["source"] in ("mininet", "virtual_testbed") and not m.get("smoke"):
            require(m.get("calibrated_generator"), "Testbed collection must use reviewed generator calibration")
        if m["source"] == "virtual_testbed":
            require(m.get("synthetic") is True and m.get("clock_mode") == "virtual_packet_time",
                    "Virtual capture must declare its synthetic clock provenance")
    return m


def resolve_device(m, ip, mac, ts):
    # Prefer time-valid IP ownership. Router MACs must never identify remote hosts.
    matches = [d["device_id"] for d in m["inventory"] for a in d.get("addresses", [])
               if a["ip"] == ip and a.get("start", m["start"]) <= ts < a.get("end", m["end"])]
    if not matches and mac:
        matches = [d["device_id"] for d in m["inventory"]
                   if d.get("mac", "").lower() == mac.lower() and not d.get("addresses")]
    require(len(set(matches)) <= 1, f"Ambiguous device identity for {ip} at {ts}")
    return matches[0] if matches else None


def validate_telemetry(r):
    require(r.get("schema_version") == VERSION, "Wrong telemetry version")
    for k in ("window_start", "uid", "orig_h", "resp_h", "proto", "flow_start",
              "orig_ip_bytes", "resp_ip_bytes", "orig_pkts", "resp_pkts", "observed_duration",
              "established", "failed", "new_flow"):
        require(k in r, f"Telemetry missing {k}")
    require(r["window_start"] % WINDOW == 0, "Unaligned telemetry window")
    require(isinstance(r["uid"], str) and bool(r["uid"]), "Missing connection UID")
    require(isinstance(r["flow_start"], (int, float)) and math.isfinite(r["flow_start"]), "Invalid flow timestamp")
    ipaddress.ip_address(r["orig_h"])
    ipaddress.ip_address(r["resp_h"])
    require(r["flow_start"] < r["window_start"] + WINDOW, "Future flow start")
    for k in ("orig_ip_bytes", "resp_ip_bytes", "orig_pkts", "resp_pkts", "observed_duration"):
        v = r[k]
        require(isinstance(v, (int, float)) and math.isfinite(v) and v >= 0, f"Invalid {k}: {v}")
        if k != "observed_duration":
            require(not isinstance(v, bool) and int(v) == v, f"{k} must be an integer counter")
    for k in ("orig_p", "resp_p"):
        if k in r and r[k] is not None:
            require(isinstance(r[k], int) and 0 <= r[k] <= 65535, f"Invalid transport port {k}")
    for k in ("established", "failed", "new_flow"):
        require(isinstance(r[k], bool), f"{k} must be boolean")
    require(not (r["failed"] and r["established"]), "Established flow marked failed")
    return r


def validate_labels(labels, manifest):
    ids = {d["device_id"] for d in manifest["inventory"]}
    for r in labels:
        require(r.get("device_id") in ids, "Label device absent from inventory")
        require(r.get("label") in (0, 1), "Labels must be binary; omit unknown labels")
        require(r.get("start", 0) < r.get("end", 0), "Invalid label interval")
        require(manifest["start"] <= r["start"] < r["end"] <= manifest["end"], "Label outside capture")
        require(r.get("evidence"), "Labels require provenance/evidence")
        if r["label"] == 1:
            require(r.get("role") == "actor", "Victim-only labels are not compromised-actor positives")
            require(r.get("attack_family") and r.get("onset") in ("from_start", "later"), "Positive label requires family/onset")
    if manifest["normal"]:
        require(not any(r["label"] == 1 for r in labels), "Normal manifest contains attack labels")


def contract():
    return {"schema_version": VERSION, "schema_hash": SCHEMA_HASH, "window_seconds": WINDOW,
            "traffic_features": FEATURES, "types": TYPES, "x_columns": X_NAMES,
            "x_dimension": len(X_NAMES), "mask_offset": MASK_OFFSET,
            "log1p_columns": [FEATURES[i] for i in LOG_FEATURES]}

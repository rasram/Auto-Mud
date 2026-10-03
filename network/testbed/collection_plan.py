"""Deterministic, inspectable plans for normal and labeled lab traffic.

This module never sends packets. Execution is restricted to the isolated runner.
"""
import hashlib
import random
from pathlib import Path

from ml.schema import VERSION, read_json, write_json, write_jsonl, require

DEVICE_TYPES = {
    "SamsungSmartThings": "hub", "AmazonEcho": "speaker", "PhilipsHue": "light",
    "BelkinWemoSwitch": "plug", "SamsungCamera": "camera", "NestDropCam": "camera",
    "AugustDoorBell": "doorbell", "BelkinWemoMotionSensor": "motion_sensor", "HPPrinter": "printer",
    "NetatmoWeatherStation": "environmental_sensor", "AwairAirQuality": "environmental_sensor",
    "WithingsSmartScale": "scale",
}
FAMILIES = ("port_scan", "lateral_connections", "exfiltration", "beaconing")


def inventory(topology, start, end):
    return [{"device_id": d, "device_type": DEVICE_TYPES.get(d.split("_")[0], "unknown"),
             "mac": f"02:00:00:00:00:{i:02x}",
             "addresses": [{"ip": topology["device_ip"][d], "start": start, "end": end}]}
            for i, d in enumerate(topology["devices"], 1)]


def child_seed(seed, device):
    return int.from_bytes(hashlib.sha256(f"{seed}:{device}".encode()).digest()[:8], "big")


def fallback_profile():
    # Explicit engineering defaults for smoke tests. Never claim these are UNSW calibrated.
    return {"flow_gap_seconds": [15, 30, 60, 90], "duration_seconds": [0.05, 0.2, 1.0],
            "request_bytes": [64, 128, 512], "response_bytes": [64, 512, 2048],
            "hour_weights": [1.0] * 24,
            "services": [{"proto": "tcp", "port": 8080, "weight": 0.7},
                         {"proto": "udp", "port": 5353, "weight": 0.3}],
            "destination_slots": 4}


def build_plan(topology, duration=86400, seed=1, profiles=None, scenario=None, actor=None,
               onset="from_start", normal_control=False, utc_phase=0):
    require(duration > 0 and duration % 60 == 0, "Duration must be a positive whole number of minutes")
    require(scenario is None or scenario in FAMILIES, "Unknown scenario")
    require(onset in ("from_start", "later"), "Unknown onset mode")
    if scenario:
        require(actor in topology["devices"], "Scenario actor must be an inventoried device")
    if profiles:
        require(profiles.get("schema_version") == "automud.generator.v1", "Recalibrate profiles using ml calibrate-traffic")
    events = []
    cloud_ips = [f"10.0.0.{i}" for i in range(100, 116)]
    for device in topology["devices"]:
        rng = random.Random(child_seed(seed, device))
        profile = profiles["devices"][device] if profiles else fallback_profile()
        t = rng.uniform(1, 5)
        while t < duration:
            service = rng.choices(profile["services"], weights=[s["weight"] for s in profile["services"]])[0]
            events.append({"device_id": device, "offset": round(t, 6), "destination": rng.choice(cloud_ips[:max(1, min(16, profile["destination_slots"]))]),
                "proto": service["proto"], "port": service["port"],
                "request_bytes": min(65536, max(1, int(rng.choice(profile["request_bytes"])))),
                "response_bytes": min(65536, max(0, int(rng.choice(profile["response_bytes"])))),
                "duration": min(10.0, max(0.01, float(rng.choice(profile["duration_seconds"])))), "kind": "normal"})
            weight = max(0.05, profile["hour_weights"][int((t + utc_phase) // 3600) % 24])
            t += max(1.0, float(rng.choice(profile["flow_gap_seconds"]))) / weight
    for i, edge in enumerate(topology["edges"]):
        rng = random.Random(child_seed(seed, f"edge:{i}"))
        t = 0
        while edge["avg_events_per_hour"] > 0:
            t += rng.expovariate(edge["avg_events_per_hour"] / 3600)
            if t >= duration:
                break
            events.append({"device_id": edge["source"], "offset": round(t, 6),
                "destination": topology["device_ip"][edge["dest"]], "proto": "tcp", "port": edge["port"],
                "request_bytes": rng.randint(*edge["payload_bytes_range"]), "response_bytes": 64,
                "duration": 0.1, "kind": "normal"})
    attack_start = 0 if onset == "from_start" else 300
    if scenario:
        require(duration > attack_start, "Scenario too short for onset")
        # Prevent background packets preceding the first malicious event for the actor.
        events = [e for e in events if not (e["device_id"] == actor and onset == "from_start" and e["offset"] < 1)]
        rng = random.Random(child_seed(seed, f"scenario:{scenario}:{actor}"))
        targets = [topology["device_ip"][d] for d in topology["devices"] if d != actor]
        interval = {"port_scan": 2, "lateral_connections": 5, "exfiltration": 2, "beaconing": 15}[scenario]
        for i, t in enumerate(range(attack_start, duration, interval)):
            dst = targets[i % len(targets)] if scenario in ("port_scan", "lateral_connections") else cloud_ips[-1]
            # Matched benign transfers use approved normal services/relationships.
            if normal_control:
                dst = cloud_ips[0]
            port = 8080 if normal_control else (20000 + i % 1000 if scenario == "port_scan" else 9090)
            events.append({"device_id": actor, "offset": float(t), "destination": dst,
                "proto": "tcp", "port": port,
                "request_bytes": 32768 if scenario == "exfiltration" else rng.randint(32, 128),
                "response_bytes": 64, "duration": 0.2 if scenario == "exfiltration" else 0.02,
                "kind": "normal_control" if normal_control else scenario,
                "expect_failure": scenario == "port_scan" and not normal_control})
    events.sort(key=lambda e: (e["offset"], e["device_id"]))
    session = f"{scenario or 'normal'}-{actor or 'household'}-{seed}-{onset}"
    return {"schema_version": "automud.collection.v1", "duration": duration, "seed": seed,
            "topology": topology, "events": events, "scenario": scenario, "actor": actor,
            "onset": onset, "normal_control": normal_control, "attack_start": attack_start,
            "session_id": session, "run_id": session + ("-control" if normal_control else "-attack" if scenario else ""),
            "calibrated": profiles is not None, "cloud_ips": cloud_ips,
            "utc_phase": utc_phase,
            "service_endpoints": sorted({(s["proto"], s["port"]) for d in topology["devices"]
                                         for s in (profiles["devices"][d] if profiles else fallback_profile())["services"]}
                                        | {("tcp", e["port"]) for e in topology["edges"]} | {("tcp", 8080), ("tcp", 9090)}),
            "limits": {"max_concurrent_per_device": 16, "max_request_bytes": 65536, "max_response_bytes": 65536}}


def label_intervals(plan, start):
    end = start + plan["duration"]
    labels = []
    for d in plan["topology"]["devices"]:
        malicious = plan["scenario"] and not plan["normal_control"] and d == plan["actor"]
        if malicious:
            if plan["attack_start"]:
                labels.append({"device_id": d, "start": start, "end": start + plan["attack_start"],
                    "label": 0, "role": "normal", "evidence": plan["run_id"]})
            labels.append({"device_id": d, "start": start + plan["attack_start"], "end": end,
                "label": 1, "role": "actor", "attack_family": plan["scenario"], "onset": plan["onset"],
                "evidence": plan["run_id"]})
        else:
            labels.append({"device_id": d, "start": start, "end": end, "label": 0,
                "role": "normal", "evidence": plan["run_id"]})
    return labels


def write_matrix(topology_path, out, profiles_path=None):
    topology = read_json(topology_path)
    profiles = read_json(profiles_path) if profiles_path else None
    actors = [next(d for d in topology["devices"] if d.startswith(prefix))
              for prefix in ("SamsungCamera_", "SamsungSmartThings_", "BelkinWemoSwitch_")]
    items = []
    for family in FAMILIES:
        for actor in actors:
            for seed in range(1, 6):
                for onset in ("from_start", "later"):
                    for control in (False, True):
                        plan = build_plan(topology, 1200, seed, profiles, family, actor, onset, control)
                        if profiles_path:
                            from ml.schema import file_hash
                            plan["profiles_file"] = str(Path(profiles_path).resolve())
                            plan["profiles_sha256"] = file_hash(profiles_path)
                        relative = plan["run_id"] + ".json"
                        write_json(Path(out) / relative, plan)
                        items.append({"plan": relative, "partition": "stage2_train" if seed <= 3 else "stage2_val" if seed == 4 else "stage2_test"})
    write_json(Path(out) / "matrix.json", {"runs": items, "sessions": len(items),
               "sequential_hours": len(items) / 3, "calibrated": profiles is not None})
    return items

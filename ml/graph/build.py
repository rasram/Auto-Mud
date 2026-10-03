"""Telemetry -> raw graph JSONL; graph construction never requires Neo4j."""
from collections import Counter, defaultdict
import math
import statistics

from ml.schema import (FEATURES, VERSION, WINDOW, SCHEMA_HASH, resolve_device,
                       validate_manifest, validate_telemetry, validate_labels, require)


def entropy(values):
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.0


def features(records, previous_destinations):
    """records contain (interval record, is_originator); all byte values are IP bytes."""
    txb = rxb = txp = rxp = initiated = inbound = 0
    destinations, ports, durations, outcomes = [], [], [], []
    protos = Counter()
    for r, orig in records:
        sent, received = ("orig", "resp") if orig else ("resp", "orig")
        txb += r[sent + "_ip_bytes"]
        rxb += r[received + "_ip_bytes"]
        txp += r[sent + "_pkts"]
        rxp += r[received + "_pkts"]
        initiated += bool(orig and r["new_flow"])
        inbound += bool(not orig and r["new_flow"])
        protos[r["proto"]] += 1
        durations.append(r["observed_duration"])
        if orig:
            destinations.append(r["resp_h"])
            if r["proto"] in ("tcp", "udp") and r.get("resp_p") is not None:
                ports.append((r["proto"], r["resp_p"]))
            if r["proto"] == "tcp" and (r["failed"] or r["established"]):
                outcomes.append(int(r["failed"]))
    n = len(records)
    values = [txb, rxb, txp, rxp, n, initiated, inbound, len(set(destinations)),
              sum(d not in previous_destinations for d in destinations) / len(destinations) if destinations else 0,
              len(set(ports)), entropy(ports),
              *(protos[p] / n if n else 0 for p in ("tcp", "udp", "icmp")),
              statistics.mean(outcomes) if outcomes else 0,
              statistics.mean(durations) if durations else 0,
              statistics.median(durations) if durations else 0,
              math.log1p(txb) - math.log1p(rxb)]
    mask = [True] * len(FEATURES)
    for idx, present in ((8, bool(destinations)), (10, bool(ports)), (11, n > 0),
                         (12, n > 0), (13, n > 0), (14, bool(outcomes)),
                         (15, bool(durations)), (16, bool(durations))):
        mask[idx] = present
    return values, mask, set(destinations)


def label_window(labels, device, start):
    overlapping = [r for r in labels if r["device_id"] == device and r["start"] < start + WINDOW and r["end"] > start]
    # Boundary windows are not quietly treated as benign or entirely malicious.
    full = [r for r in overlapping if r["start"] <= start and r["end"] >= start + WINDOW]
    if len({r["label"] for r in overlapping}) > 1 or not full:
        return -1, None
    return full[0]["label"], {k: full[0].get(k) for k in ("attack_family", "onset", "start", "role")}


def build_snapshots(telemetry, manifest, labels=()):
    """Stream ordered interval rows. Memory is bounded by one window plus peer history."""
    validate_manifest(manifest)
    labels = list(labels)
    validate_labels(labels, manifest)
    inventory = sorted(manifest["inventory"], key=lambda d: d["device_id"])
    index = {d["device_id"]: i for i, d in enumerate(inventory)}
    history = defaultdict(set)
    edge_history = set()
    iterator = iter(telemetry)
    pending = next(iterator, None)
    last_window = -float("inf")
    for start in range(int(manifest["start"]), int(manifest["end"]), WINDOW):
        grouped = defaultdict(list)
        pairs = defaultdict(list)
        seen = set()
        while pending is not None and pending["window_start"] < start + WINDOW:
            r = validate_telemetry(pending)
            require(r["window_start"] >= last_window, "Telemetry must be sorted by window_start")
            last_window = r["window_start"]
            require(r["window_start"] >= start, "Telemetry predates manifest or repeats an emitted window")
            require(r["uid"] not in seen, f"Duplicate flow interval {r['uid']} at {start}")
            seen.add(r["uid"])
            orig = resolve_device(manifest, r["orig_h"], r.get("orig_mac"), start)
            resp = resolve_device(manifest, r["resp_h"], r.get("resp_mac"), start)
            if orig:
                grouped[orig].append((r, True))
            if resp and resp != orig:
                grouped[resp].append((r, False))
            if orig and resp and orig != resp:
                pairs[(orig, resp)].append(r)
            pending = next(iterator, None)
        nodes = []
        for d in inventory:
            device = d["device_id"]
            values, mask, destinations = features(grouped[device], history[device])
            available = manifest["capture_complete"] and not any(
                o["start"] < start + WINDOW and o["end"] > start and o.get("device_id", device) == device
                for o in manifest.get("outages", []))
            y, details = label_window(labels, device, start)
            if manifest["normal"] and not labels:
                y = 0
            nodes.append({"device_id": device, "device_type": d["device_type"], "features": values,
                          "feature_mask": mask if available else [False] * len(mask),
                          "active": bool(grouped[device]), "available": available,
                          "label": y if available else -1, "label_details": details})
            if available:
                history[device].update(destinations)
        edges = []
        for pair, rows in sorted(pairs.items()):
            if not all(nodes[index[d]]["available"] for d in pair):
                continue
            edges.append({"source": index[pair[0]], "target": index[pair[1]],
                          "ip_bytes": sum(r["orig_ip_bytes"] + r["resp_ip_bytes"] for r in rows),
                          "packets": sum(r["orig_pkts"] + r["resp_pkts"] for r in rows),
                          "flow_count": len(rows), "new_edge": pair not in edge_history,
                          "protocols": dict(Counter(r["proto"] for r in rows)),
                          "ports": sorted({f"{r['proto']}/{r['resp_p']}" for r in rows
                                           if r["proto"] in ("tcp", "udp") and r.get("resp_p") is not None}),
                          "confirmed": any(r["established"] or (r["proto"] != "tcp" and r["resp_pkts"] > 0) for r in rows)})
        edge_history.update(pairs)
        yield {"schema_version": VERSION, "schema_hash": SCHEMA_HASH, "run_id": manifest["run_id"],
               "session_id": manifest["session_id"], "source": manifest["source"], "normal": manifest["normal"],
               "window_start": start, "window_seconds": WINDOW, "nodes": nodes, "edges": edges}
    require(pending is None, "Telemetry extends beyond manifest end")

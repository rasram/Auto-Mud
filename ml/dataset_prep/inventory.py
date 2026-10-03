"""Read-only, bounded header inventory; never invent public per-device labels."""
import csv
from datetime import datetime, timezone
from pathlib import Path

from ml.schema import read_json, write_json


def capture_start(path):
    """Read only the first packet; filenames need not follow UTC boundaries."""
    from scapy.utils import RawPcapReader
    with RawPcapReader(str(path)) as reader:
        _, meta = next(reader)
    ts = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol if hasattr(meta, "tshigh") else meta.sec + meta.usec / 1_000_000
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def attack_workbook(path):
    """Inspect source roles, retaining all workbook evidence without making labels."""
    from openpyxl import load_workbook
    workbook = load_workbook(path, read_only=True, data_only=True)
    devices = []
    for row in list(workbook["Attacks"].values)[1:]:
        if row[0] and row[1]:
            devices.append({"mac": str(row[0]).lower(), "ip": str(row[1]).lstrip("\ufeff"),
                            "device_type": str(row[4]), "start": str(row[2]), "end": str(row[3])})
    known_ips = {d["ip"] for d in devices}
    experiments = []
    for row in workbook["Experiments"].values:
        if row[0] and row[0] != "Attack" and row[4]:
            actor_ip = str(row[4]).lstrip("\ufeff")
            experiments.append({"attack": str(row[0]), "capture_reference": str(row[1]),
                                "annotation_reference": str(row[2]) if row[2] else None,
                                "direction": str(row[3]), "attacker_ip": actor_ip,
                                "victim": str(row[5]) if row[5] else None,
                                "actor_is_listed_device": actor_ip in known_ips})
    return {"path": str(path), "devices": devices, "experiments": experiments,
            "actor_ips": sorted({r["attacker_ip"] for r in experiments}),
            "actor_ips_matching_listed_devices": sorted({r["attacker_ip"] for r in experiments if r["actor_is_listed_device"]}),
            "head_c_label_policy": "Experiment targets are not positive compromised-device labels. Review actors and packet timing before any label."}


def unsw_attack_identities(workbook_path, out, existing="configs/gnn/unsw-identities.json"):
    """Export the workbook's ten observed target identities for manifest review."""
    known = {d["mac"].lower(): d for d in read_json(existing)["inventory"]}
    type_map = {"WEMO Motion Sensor": "motion_sensor", "WEMO Power Switch": "plug",
                "Samsung Camera": "camera", "TP Link Plug": "plug", "Netatmo Camera": "camera",
                "Huebulb": "light", "AmazonEcho": "speaker", "lifx": "light"}
    workbook = attack_workbook(workbook_path)
    identities = []
    for d in workbook["devices"]:
        previous = known.get(d["mac"])
        identities.append({"device_id": previous["device_id"] if previous else "UNSW_" + d["mac"].replace(":", ""),
                           "device_type": previous["device_type"] if previous else type_map.get(d["device_type"], "unknown"),
                           "mac": d["mac"], "source_device_type": d["device_type"],
                           "reviewed_ip": d["ip"]})
    from ml.schema import require
    require(len(identities) == len({d["mac"] for d in identities}), "Duplicate attack workbook MAC identities")
    write_json(out, {"inventory": identities,
                     "review_required": "These are observed IoT target identities, not compromised-actor labels. Check against PCAPs."})
    return {"identities": len(identities), "out": str(out)}


def audit(cic_root, unsw_normal, unsw_attack, topology, out):
    cic_root, unsw_normal, unsw_attack = map(Path, (cic_root, unsw_normal, unsw_attack))
    topology = read_json(topology)
    report = {"cic": {}, "unsw_normal": {}, "unsw_attack": {}, "exclusions": []}
    for key in ("CSV", "MERGED_CSV"):
        files = sorted((cic_root / key).rglob("*.csv"))
        headers = {}
        for p in files:
            with p.open(encoding="utf-8-sig") as h:
                header = tuple(next(csv.reader(h)))
            headers.setdefault(header, []).append(str(p))
        report["cic"][key] = [{"columns": list(h), "file_count": len(ps), "example": ps[0]} for h, ps in headers.items()]
    report["cic"]["pcaps"] = [{"path": str(p), "bytes": p.stat().st_size,
        "role": "normal_candidate" if p.stem.startswith("BenignTraffic") else "needs_verified_actor_and_interval"}
        for p in sorted(cic_root.glob("*.pcap*"))]
    report["exclusions"].append("CIC aggregate CSVs have no device identity/time fields; cannot reconstruct canonical device graphs")
    report["unsw_normal"]["selected_pcaps"] = [{"device_id": d, "path": str(unsw_normal / "pcaps" / (d.removesuffix("_flows") + ".pcap")),
        "exists": (unsw_normal / "pcaps" / (d.removesuffix("_flows") + ".pcap")).exists()} for d in topology["devices"]]
    annotation_files = sorted((unsw_attack / "annotations").rglob("*.csv"))
    annotations, dates, malformed = [], set(), []
    for p in annotation_files:
        with p.open(encoding="utf-8-sig") as h:
            for line, row in enumerate(csv.reader(h), 1):
                try:
                    start, end = float(row[0]), float(row[1])
                    if len(row) != 4 or end <= start or "features" in row[3].lower():
                        raise ValueError("Unexpected column count/order")
                    dates.add(datetime.fromtimestamp(start, timezone.utc).date().isoformat())
                    annotations.append({"file": str(p), "line": line, "start": start, "end": end,
                                        "impacted_mac": p.stem, "attack_family": row[3], "role": "victim_or_impacted_unknown"})
                except (ValueError, IndexError) as exc:
                    malformed.append({"file": str(p), "line": line, "row": row, "error": str(exc)})
    stats = []
    for p in sorted((unsw_attack / "flowdata").rglob("*.csv")):
        with p.open(encoding="utf-8-sig") as h:
            reader = csv.reader(h)
            header = next(reader)
            rows = sum(1 for _ in reader)
        stats.append({"path": str(p), "columns": header, "row_count": rows,
                      "compatible": False, "reason": "Policy buckets lack individual peers, connection timing/state and graph context"})
    capture_files = sorted(unsw_attack.rglob("*.pcap*"))
    workbook_path = unsw_attack / "attackinfo.xlsx"
    report["unsw_attack"].update(flowstats=stats, annotations=annotations, malformed_annotations=malformed,
        required_capture_dates=sorted(dates),
        raw_pcaps=[{"path": str(p), "bytes": p.stat().st_size,
                     "first_packet_utc": capture_start(p)} for p in capture_files],
        attack_workbook=attack_workbook(workbook_path) if workbook_path.exists() else None,
        acquisition_source="https://iotanalytics.unsw.edu.au/attack-data.html",
        required_metadata=["verified actor MAC/IP and role", "attack interval", "capture timezone/bounds", "device inventory and leases"])
    write_json(out, report)
    return report

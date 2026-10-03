"""Bootstrap public capture manifests from VERIFIED MAC identities.

This never infers malicious actors or labels from an attack filename.
"""
import math
from collections import defaultdict
from pathlib import Path

from ml.schema import VERSION, read_jsonl, read_json, write_json, require


def make_manifest(telemetry, identities, source, run_id, out, normal=False):
    identities = read_json(identities)["inventory"]
    by_mac = {d["mac"].lower(): d for d in identities}
    require(len(by_mac) == len(identities), "Duplicate MAC identities")
    observed = defaultdict(lambda: defaultdict(set))
    first, last = float("inf"), -float("inf")
    for r in read_jsonl(telemetry):
        first = min(first, max(r["window_start"], r["flow_start"]))
        last = max(last, r["window_start"])
        for prefix in ("orig", "resp"):
            mac = r.get(prefix + "_mac", "").lower()
            if mac in by_mac:
                observed[mac][r[prefix + "_h"]].add(int(r["window_start"]))
    require(observed, "None of the verified identities appears in telemetry; load MAC logging or supply correct identities")
    start, end = int(math.ceil(first / 60) * 60), int(last)
    require(end > start, "Not enough complete capture windows")
    inventory = []
    for mac, ips in sorted(observed.items()):
        leases = []
        for ip, windows in sorted(ips.items()):
            active = sorted(w for w in windows if start <= w < end)
            for w in active:
                if leases and leases[-1]["ip"] == ip and leases[-1]["end"] == w:
                    leases[-1]["end"] = w + 60
                else:
                    leases.append({"ip": ip, "start": w, "end": w + 60})
        inventory.append({**by_mac[mac], "addresses": leases})
    extraction_path = Path(telemetry).parent / "extraction.json"
    extraction = read_json(extraction_path) if extraction_path.exists() else {}
    manifest = {"schema_version": VERSION, "run_id": run_id, "session_id": run_id, "source": source,
        "normal": normal, "start": start, "end": end, "inventory": inventory,
        "capture_complete": False, "replay_speed": 1,
        "capture_hashes": [i["sha256"] for i in extraction.get("inputs", [])],
        "review_required": ["Confirm capture continuity and absence of missing parts/drop artifacts",
                            "Set capture_complete true only after QC", "For attacks supply verified actor interval labels",
                            "Keep all parts of this session in one supervised split"]}
    write_json(out, manifest)
    return {"manifest": str(out), "devices": len(inventory), "review_required": True}

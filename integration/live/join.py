import time

from integration.live.common import canonical_digest


JOIN_FIELDS = ("run_id", "session_id", "sensor_id", "inventory_version", "window_start", "window_end", "observation_kind")


def join_evidence(window, gnn=None, mud=None, now=time.time):
    mismatches = []
    for branch_name, branch in (("gnn", gnn), ("mud", mud)):
        if branch is None:
            continue
        for field in JOIN_FIELDS:
            if branch.get(field) != window.get(field):
                mismatches.append(f"{branch_name}.{field}")
    if mismatches:
        raise ValueError("Cross-window/identity evidence join rejected: " + ", ".join(mismatches))
    missing = [name for name, value in (("gnn", gnn), ("mud", mud)) if value is None]
    joined = {
        "schema_version": "automud.joined-evidence.v1",
        **{field: window[field] for field in JOIN_FIELDS},
        "observation_id": (gnn or {}).get("observation_id"),
        "gnn_evidence": gnn,
        "mud_evidence": mud,
        "branch_status": {
            "gnn": "available" if gnn is not None else "unavailable",
            "mud": "available" if mud is not None and mud["health"]["available"] else "unavailable",
        },
        "partial": bool(missing or (mud and not mud["health"]["available"])),
        "joined_at": now(),
    }
    joined["join_id"] = canonical_digest({k: v for k, v in joined.items() if k != "joined_at"})
    return joined

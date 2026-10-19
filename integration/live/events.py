import json
import os
import threading
import time
from pathlib import Path

from integration.live.common import canonical_digest


TRACE_FIELDS = ("run_id", "session_id", "sensor_id", "inventory_version", "window_start", "window_end")


def _trace_id(payload):
    candidate = payload.get("request", payload) if isinstance(payload, dict) else {}
    identity = {field: candidate.get(field) for field in TRACE_FIELDS}
    if all(value is not None for value in identity.values()):
        return canonical_digest(identity)
    for name in ("observation_id", "join_id", "decision_id"):
        if isinstance(candidate, dict) and candidate.get(name):
            return candidate[name]
    return None


class EventStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def append(self, kind, payload):
        record = {
            "schema_version": "automud.event.v1",
            "recorded_at": time.time(),
            "kind": kind,
            "trace_id": _trace_id(payload),
            "payload": payload,
        }
        record["event_id"] = canonical_digest(record)
        body = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        return record

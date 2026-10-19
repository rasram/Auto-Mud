import json
import os
import threading
import time
from pathlib import Path


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
            "payload": payload,
        }
        body = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        return record

import argparse
import json
import time
from pathlib import Path

from integration.live.common import atomic_json
from integration.live.config import interval_inventory, load_deployment
from integration.live.orchestrator import Orchestrator


def _json_lines(path):
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON line {path}:{number}: {error}") from error
    return rows


def build_window(deployment, telemetry_path, health_path, window_start, run_id, session_id):
    start, end = int(window_start), int(window_start) + 60
    runtime_path = Path(telemetry_path).parent.parent / "runtime.json"
    lease_start = start
    if runtime_path.exists():
        with runtime_path.open(encoding="utf-8") as handle:
            runtime = json.load(handle)
        if runtime.get("run_id") != run_id or runtime.get("inventory_version") != deployment["inventory_version"]:
            raise ValueError("Runtime inventory does not match the finalizer session")
        lease_start = int(runtime["started_at"])
    telemetry = []
    for row in _json_lines(telemetry_path):
        if int(float(row.get("window_start", -1))) != start:
            continue
        normalized = dict(row)
        normalized["window_start"] = start
        for name in ("orig_p", "resp_p", "orig_ip_bytes", "resp_ip_bytes", "orig_pkts", "resp_pkts"):
            if normalized.get(name) is not None:
                normalized[name] = int(normalized[name])
        telemetry.append(normalized)
    health_rows = {int(float(row["window_start"])): row for row in _json_lines(health_path) if "window_start" in row}
    observed = health_rows.get(start)
    if observed:
        drops = observed.get("capture_drops")
        health = {
            "complete": bool(observed.get("complete") and observed.get("watermark", 0) >= end),
            "sensor_healthy": bool(observed.get("sensor_healthy")),
            "clock_synchronized": bool(observed.get("clock_synchronized")),
            "capture_drops": int(drops) if drops is not None else None,
            "unavailable_device_ids": observed.get("unavailable_device_ids", []),
        }
        watermark = float(observed.get("watermark", end))
    else:
        health = {
            "complete": False, "sensor_healthy": False, "clock_synchronized": False,
            "capture_drops": None, "unavailable_device_ids": [],
        }
        watermark = end
    return {
        "schema_version": "automud.live-window.v1",
        "observation_kind": deployment["observation_kind"],
        "run_id": run_id, "session_id": session_id,
        "sensor_id": deployment["network"]["sensor_id"],
        "inventory_version": deployment["inventory_version"],
        "window_start": start, "window_end": end, "watermark": watermark,
        "inventory": interval_inventory(deployment, lease_start),
        "health": health, "telemetry": telemetry,
    }


class DurableFinalizer:
    def __init__(self, deployment, telemetry_path, health_path, run_id, session_id):
        self.deployment = deployment
        self.telemetry_path = Path(telemetry_path)
        self.health_path = Path(health_path)
        self.run_id, self.session_id = run_id, session_id
        self.queue = Path(deployment["paths"]["queue"])
        self.pending = self.queue / "pending"
        self.accepted = self.queue / "accepted"
        self.pending.mkdir(parents=True, exist_ok=True)
        self.accepted.mkdir(parents=True, exist_ok=True)
        self.orchestrator = Orchestrator(deployment)

    def finalize(self, start):
        path = self.pending / f"{int(start)}.json"
        accepted_path = self.accepted / f"{int(start)}.json"
        if accepted_path.exists():
            with accepted_path.open(encoding="utf-8") as handle:
                return json.load(handle)
        if not path.exists():
            atomic_json(path, build_window(self.deployment, self.telemetry_path, self.health_path, start, self.run_id, self.session_id))
        with path.open(encoding="utf-8") as handle:
            window = json.load(handle)
        result = self.orchestrator.process(window)
        atomic_json(accepted_path, result)
        path.unlink()
        return result

    def retry_pending(self):
        results = []
        for path in sorted(self.pending.glob("*.json"), key=lambda item: int(item.stem)):
            results.append(self.finalize(int(path.stem)))
        return results


def main():
    parser = argparse.ArgumentParser(description="Persist, submit, and join completed UTC Zeek windows")
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--telemetry", required=True)
    parser.add_argument("--health", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--window-start", type=int)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--close-delay", type=float, default=5.0)
    args = parser.parse_args()
    if args.daemon == (args.window_start is not None):
        parser.error("choose exactly one of --daemon or --window-start")
    deployment = load_deployment(args.config)
    finalizer = DurableFinalizer(deployment, args.telemetry, args.health, args.run_id, args.session_id)
    finalizer.retry_pending()
    if args.window_start is not None:
        print(json.dumps(finalizer.finalize(args.window_start), indent=2, sort_keys=True))
        return
    completed = set()
    while True:
        now = time.time()
        start = int((now - args.close_delay) // 60) * 60 - 60
        if start >= 0 and start not in completed:
            finalizer.finalize(start)
            completed.add(start)
        time.sleep(1)


if __name__ == "__main__":
    main()

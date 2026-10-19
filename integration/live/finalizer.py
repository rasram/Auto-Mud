import argparse
import fcntl
import ipaddress
import json
import os
import random
import time
from pathlib import Path

from integration.live.common import atomic_json, canonical_digest
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


def _runtime(path, required=None):
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if required is None:
        required = {
            "run_id", "session_id", "started_at", "inventory_version",
            "telemetry_log", "health_log",
        }
    missing = required - set(value)
    if missing:
        raise ValueError("Runtime receipt missing: " + ", ".join(sorted(missing)))
    return value


def _runtime_process_active(runtime):
    if runtime.get("active") is not True:
        return False
    pid = runtime.get("topology_pid")
    expected_start = runtime.get("topology_process_start_ticks")
    expected_boot = runtime.get("boot_id")
    if pid is None:
        return True
    try:
        if expected_boot and Path("/proc/sys/kernel/random/boot_id").read_text().strip() != expected_boot:
            return False
        stat = Path(f"/proc/{int(pid)}/stat").read_text().split()
        if expected_start is not None and int(stat[21]) != int(expected_start):
            return False
        command = Path(f"/proc/{int(pid)}/cmdline").read_bytes().replace(b"\0", b" ")
        return b"network.testbed.live_topology" in command or b"live_topology.py" in command
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        return False


def _dns_evidence(path, sensor_id, window_start, window_end):
    result = []
    for row in _json_lines(path):
        observed = float(row.get("ts", -1))
        if observed < 0 or observed >= window_end:
            continue
        answers = row.get("answers") or []
        ttls = row.get("TTLs") or row.get("ttls") or []
        addresses = []
        lifetimes = []
        for index, answer in enumerate(answers):
            try:
                addresses.append(str(ipaddress.ip_address(answer)))
                lifetimes.append(float(ttls[index]) if index < len(ttls) else 0.0)
            except (ValueError, TypeError):
                continue
        if not addresses:
            continue
        ttl = min((value for value in lifetimes if value > 0), default=0.0)
        if ttl <= 0 or observed + ttl <= window_start:
            continue
        result.append({
            "schema_version": "automud.name-evidence.v1",
            "sensor_id": sensor_id, "name": row.get("query", ""),
            "addresses": sorted(set(addresses)), "valid_from": observed,
            "valid_until": observed + ttl,
        })
    return result


def build_window(deployment, telemetry_path, health_path, window_start, run_id, session_id):
    start, end = int(window_start), int(window_start) + 60
    runtime_path = Path(telemetry_path).parent.parent / "runtime.json"
    lease_start = start
    if runtime_path.exists():
        runtime = _runtime(
            runtime_path,
            required={"run_id", "started_at", "inventory_version"},
        )
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
    health_rows = {
        int(float(row["window_start"])): row
        for row in _json_lines(health_path) if "window_start" in row
    }
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
        "inventory": interval_inventory(
            deployment, lease_start if deployment["schema_version"] == "automud.deployment.v1" else start,
            None if deployment["schema_version"] == "automud.deployment.v1" else end,
        ),
        "health": health, "telemetry": telemetry,
    }


class DurableFinalizer:
    def __init__(self, deployment, telemetry_path, health_path, run_id, session_id, now=time.time):
        self.deployment = deployment
        self.telemetry_path = Path(telemetry_path)
        self.health_path = Path(health_path)
        self.dns_path = self.telemetry_path.parent / "dns.log"
        self.run_id, self.session_id = run_id, session_id
        self.now = now
        self.queue = Path(deployment["paths"]["queue"])
        self.run_token = canonical_digest([run_id, session_id])[:16]
        self.run_queue = self.queue / "runs" / self.run_token
        self.pending = self.run_queue / "pending"
        self.accepted = self.run_queue / "accepted"
        self.status_path = self.queue / "status.json"
        self.run_status_path = self.run_queue / "status.json"
        self.lock_path = self.queue / "finalizer.lock"
        self.pending.mkdir(parents=True, exist_ok=True)
        self.accepted.mkdir(parents=True, exist_ok=True)
        self.orchestrator = Orchestrator(deployment, now=now)
        self._status = self._read_status()

    @classmethod
    def from_runtime(cls, deployment, runtime_path, now=time.time):
        runtime = _runtime(runtime_path)
        if runtime["inventory_version"] != deployment["inventory_version"]:
            raise ValueError("Current runtime uses another inventory version")
        return cls(
            deployment, runtime["telemetry_log"], runtime["health_log"],
            runtime["run_id"], runtime["session_id"], now=now,
        )

    def _read_status(self):
        if self.run_status_path.exists():
            with self.run_status_path.open(encoding="utf-8") as handle:
                value = json.load(handle)
            if value.get("run_id") == self.run_id and value.get("session_id") == self.session_id:
                return value
        return {
            "schema_version": "automud.finalizer-status.v1",
            "run_id": self.run_id, "session_id": self.session_id,
            "attempts": {}, "last_accepted_window": None, "last_watermark": None,
            "last_error": None, "updated_at": self.now(),
        }

    def _status_snapshot(self):
        pending_starts = sorted(int(path.stem) for path in self.pending.glob("*.json"))
        snapshot = dict(self._status)
        snapshot.update({
            "queue_depth": len(pending_starts),
            "oldest_pending_window": pending_starts[0] if pending_starts else None,
            "oldest_pending_age_seconds": (
                max(0.0, self.now() - pending_starts[0] - 60) if pending_starts else None
            ),
            "coordinator": self.orchestrator.coordinator.status(),
            "updated_at": self.now(),
        })
        return snapshot

    def _write_status(self):
        self._status = self._status_snapshot()
        atomic_json(self.run_status_path, self._status)
        atomic_json(self.status_path, self._status)

    def status(self):
        return self._status_snapshot()

    def finalize(self, start):
        start = int(start)
        path = self.pending / f"{start}.json"
        accepted_path = self.accepted / f"{start}.json"
        if accepted_path.exists():
            with accepted_path.open(encoding="utf-8") as handle:
                return json.load(handle)
        if not path.exists():
            payload = build_window(
                self.deployment, self.telemetry_path, self.health_path,
                start, self.run_id, self.session_id,
            )
            atomic_json(path, payload)
        with path.open(encoding="utf-8") as handle:
            window = json.load(handle)
        entry = self._status["attempts"].setdefault(str(start), {
            "payload_hash": canonical_digest(window), "attempts": 0,
            "first_attempt_at": self.now(), "last_attempt_at": None,
            "next_retry_at": None, "last_error": None,
        })
        if entry["payload_hash"] != canonical_digest(window):
            raise ValueError("Pending payload changed after persistence")
        entry["attempts"] += 1
        entry["last_attempt_at"] = self.now()
        try:
            names = _dns_evidence(
                self.dns_path, self.deployment["network"]["sensor_id"],
                window["window_start"], window["window_end"],
            )
            result = self.orchestrator.process(window, name_evidence=names)
        except Exception as error:
            entry["last_error"] = f"{type(error).__name__}: {error}"
            delay = min(60.0, 0.5 * (2 ** min(entry["attempts"] - 1, 7)))
            entry["next_retry_at"] = self.now() + delay + random.uniform(0, delay * 0.1)
            self._status["last_error"] = entry["last_error"]
            self._write_status()
            raise
        atomic_json(accepted_path, result)
        path.unlink()
        entry["last_error"] = None
        entry["next_retry_at"] = None
        self._status["last_accepted_window"] = start
        self._status["last_error"] = None
        self._write_status()
        return result

    def retry_pending(self):
        results = []
        for path in sorted(self.pending.glob("*.json"), key=lambda item: int(item.stem)):
            entry = self._status["attempts"].get(path.stem, {})
            if entry.get("next_retry_at") and self.now() < entry["next_retry_at"]:
                continue
            try:
                results.append(self.finalize(int(path.stem)))
            except Exception:
                break
        self._write_status()
        return results

    def eligible_windows(self, incomplete_deadline_seconds=30, close_delay=5):
        runtime_path = self.telemetry_path.parent.parent / "runtime.json"
        runtime = _runtime(runtime_path)
        first = int(runtime["started_at"] // 60) * 60
        current = self.now()
        health = {
            int(float(row["window_start"])): row
            for row in _json_lines(self.health_path) if "window_start" in row
        }
        if health:
            self._status["last_watermark"] = max(float(row.get("watermark", 0)) for row in health.values())
        if runtime.get("stopped_at") is not None:
            runtime_end = min(current, float(runtime["stopped_at"]))
        elif _runtime_process_active(runtime):
            runtime_end = current
        elif health:
            # Legacy receipts have no lifecycle marker. Bound them to the last
            # sensor watermark so a restart cannot invent an endless sequence
            # of incomplete windows for a stopped topology.
            runtime_end = min(current, max(float(row.get("watermark", 0)) for row in health.values()))
        else:
            return []
        latest = int((runtime_end - close_delay) // 60) * 60 - 60
        result = []
        for start in range(first, latest + 1, 60):
            if (self.accepted / f"{start}.json").exists():
                continue
            row = health.get(start)
            progressed = bool(row and float(row.get("watermark", 0)) >= start + 60)
            expired = current >= start + 60 + incomplete_deadline_seconds
            if progressed or expired:
                result.append(start)
        return result

    def run_once(self, incomplete_deadline_seconds=30, close_delay=5):
        results = self.retry_pending()
        for start in self.eligible_windows(incomplete_deadline_seconds, close_delay):
            if (self.pending / f"{start}.json").exists():
                continue
            try:
                results.append(self.finalize(start))
            except Exception:
                break
        results.extend(self.orchestrator.process_due())
        self._write_status()
        return results

    def acquire_lock(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            handle.close()
            raise RuntimeError("Another finalizer owns the deployment queue") from error
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        return handle


def _daemon_from_runtime(deployment, runtime_path, incomplete_deadline, close_delay):
    queue = Path(deployment["paths"]["queue"])
    queue.mkdir(parents=True, exist_ok=True)
    lock_path = queue / "finalizer.lock"
    handle = lock_path.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        handle.close()
        raise RuntimeError("Another finalizer owns the deployment queue") from error
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    current_identity = None
    finalizer = None
    try:
        while True:
            try:
                runtime = _runtime(runtime_path)
                identity = (runtime["run_id"], runtime["session_id"])
                if identity != current_identity:
                    finalizer = DurableFinalizer.from_runtime(deployment, runtime_path)
                    current_identity = identity
                finalizer.run_once(incomplete_deadline, close_delay)
            except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError) as error:
                atomic_json(queue / "status.json", {
                    "schema_version": "automud.finalizer-status.v1",
                    "run_id": current_identity[0] if current_identity else None,
                    "session_id": current_identity[1] if current_identity else None,
                    "last_error": f"{type(error).__name__}: {error}",
                    "updated_at": time.time(),
                })
            time.sleep(1)
    finally:
        handle.close()


def _arguments():
    parser = argparse.ArgumentParser(description="Persist, submit and join completed UTC Zeek windows")
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--runtime-current")
    parser.add_argument("--telemetry")
    parser.add_argument("--health")
    parser.add_argument("--run-id")
    parser.add_argument("--session-id")
    parser.add_argument("--window-start", type=int)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--close-delay", type=float, default=5.0)
    parser.add_argument("--incomplete-deadline", type=float, default=30.0)
    args = parser.parse_args()
    if sum(bool(value) for value in (args.daemon, args.once, args.status, args.window_start is not None)) != 1:
        parser.error("choose exactly one of --daemon, --once, --status or --window-start")
    explicit = all((args.telemetry, args.health, args.run_id, args.session_id))
    if bool(args.runtime_current) == explicit:
        parser.error("provide --runtime-current or all explicit telemetry/health/run/session arguments")
    return args


def main():
    args = _arguments()
    deployment = load_deployment(args.config)
    if args.daemon and args.runtime_current:
        _daemon_from_runtime(
            deployment, args.runtime_current,
            args.incomplete_deadline, args.close_delay,
        )
        return
    finalizer = (
        DurableFinalizer.from_runtime(deployment, args.runtime_current)
        if args.runtime_current else
        DurableFinalizer(deployment, args.telemetry, args.health, args.run_id, args.session_id)
    )
    if args.status:
        print(json.dumps(finalizer.status(), indent=2, sort_keys=True))
        return
    lock = finalizer.acquire_lock()
    try:
        if args.window_start is not None:
            print(json.dumps(finalizer.finalize(args.window_start), indent=2, sort_keys=True))
            return
        if args.once:
            print(json.dumps(finalizer.run_once(args.incomplete_deadline, args.close_delay), indent=2, sort_keys=True))
            return
        while True:
            finalizer.run_once(args.incomplete_deadline, args.close_delay)
            time.sleep(1)
    finally:
        lock.close()


if __name__ == "__main__":
    main()

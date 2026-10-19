import argparse
import json
import mimetypes
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from integration.live.config import load_deployment


def _read_json(path, default):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def _events(path, limit=200, kind=None):
    rows = []
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if kind and row.get("kind") != kind:
                    continue
                rows.append(row)
    except FileNotFoundError:
        return []
    return rows[-max(1, min(int(limit), 2000)):]


def _traces(rows):
    grouped = defaultdict(list)
    decision_to_trace = {}
    for row in rows:
        payload = row.get("payload") or {}
        trace = row.get("trace_id")
        if row.get("kind") == "decision" and trace:
            decision_to_trace[payload.get("decision_id")] = trace
        if not trace and isinstance(payload, dict):
            request = payload.get("request") or {}
            trace = decision_to_trace.get(request.get("decision_id"))
        grouped[trace or "unlinked"].append(row)
    result = []
    for trace_id, events in grouped.items():
        times = {event["kind"]: event["recorded_at"] for event in events}
        window = next((event["payload"] for event in events if event["kind"] == "window"), {})
        first_flow = min(
            (float(flow["flow_start"]) for flow in window.get("telemetry", []) if flow.get("flow_start") is not None),
            default=None,
        )
        effect = next((
            event["payload"].get("installed_at")
            for event in events if event["kind"] == "controller_outcome"
        ), None)
        result.append({
            "trace_id": trace_id,
            "window_start": window.get("window_start"),
            "window_end": window.get("window_end"),
            "observation_kind": window.get("observation_kind"),
            "event_kinds": [event["kind"] for event in events],
            "timestamps": times,
            "latency_seconds": {
                "packet_to_window_close": (
                    window.get("window_end") - first_flow if first_flow is not None else None
                ),
                "window_close_to_join": (
                    times.get("joined_evidence") - window.get("window_end")
                    if times.get("joined_evidence") is not None and window.get("window_end") is not None else None
                ),
                "join_to_decision": (
                    times.get("decision") - times.get("joined_evidence")
                    if times.get("decision") is not None and times.get("joined_evidence") is not None else None
                ),
                "decision_to_install": (
                    effect - times.get("decision")
                    if effect is not None and times.get("decision") is not None else None
                ),
                "packet_to_install": effect - first_flow if effect is not None and first_flow is not None else None,
            },
            "events": events,
        })
    return sorted(result, key=lambda item: item["window_start"] or 0, reverse=True)


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, address, deployment, static_root):
        super().__init__(address, DashboardHandler)
        self.deployment = deployment
        self.static_root = Path(static_root).resolve()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "AutoMUDDashboard/1"

    def log_message(self, fmt, *args):
        return

    def _json(self, value, status=200):
        body = json.dumps(value, sort_keys=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        deployment = self.server.deployment
        if parsed.path == "/api/status":
            status = _read_json(Path(deployment["paths"]["queue"]) / "status.json", {})
            self._json({
                "schema_version": "automud.dashboard-status.v1",
                "deployment_id": deployment["deployment_id"],
                "inventory_version": deployment["inventory_version"],
                "observation_kind": deployment["observation_kind"],
                "decision_mode": deployment["decision"]["mode"],
                "automatic_enforcement_enabled": bool(
                    deployment["observation_kind"] == "live"
                    and deployment["decision"]["mode"] == "enforce"
                ),
                "finalizer": status,
            })
            return
        query = parse_qs(parsed.query)
        if parsed.path == "/api/events":
            self._json({"events": _events(
                deployment["paths"]["event_log"],
                limit=query.get("limit", [200])[0], kind=query.get("kind", [None])[0],
            )})
            return
        if parsed.path == "/api/traces":
            rows = _events(deployment["paths"]["event_log"], limit=query.get("limit", [1000])[0])
            self._json({"traces": _traces(rows)})
            return
        relative = "index.html" if parsed.path == "/" else parsed.path.lstrip("/")
        target = (self.server.static_root / relative).resolve()
        if self.server.static_root not in target.parents and target != self.server.static_root:
            self._json({"status": "not_found"}, 404)
            return
        if not target.is_file():
            self._json({"status": "not_found"}, 404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="Read-only AutoMUD trace dashboard")
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8090, type=int)
    parser.add_argument("--static-root", default="dashboard/frontend")
    args = parser.parse_args()
    deployment = load_deployment(args.config)
    server = DashboardServer((args.host, args.port), deployment, args.static_root)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

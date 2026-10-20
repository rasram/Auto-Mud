"""Read-only operational views and guarded human overrides for AutoMUD."""

import argparse
import json
import mimetypes
import os
import secrets
import statistics
import tempfile
import threading
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

from integration.live.config import active_binding, load_deployment


MAX_EVENTS = 20000
MAX_BODY_BYTES = 16384
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def _read_json(path, default):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError):
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
                if not kind or row.get("kind") == kind:
                    rows.append(row)
    except FileNotFoundError:
        return []
    return rows[-max(1, min(int(limit), MAX_EVENTS)):]


def _event(events, kind):
    return next((row for row in reversed(events) if row.get("kind") == kind), None)


def _payload(events, kind):
    return (_event(events, kind) or {}).get("payload") or {}


def _trace_health(window, gnn, mud, joined):
    sensor = window.get("health") or {}
    freshness = gnn.get("integration_health") or {}
    branch = joined.get("branch_status") or {}
    sensor_ok = bool(
        sensor.get("complete") and sensor.get("sensor_healthy")
        and sensor.get("clock_synchronized") and sensor.get("capture_drops") == 0
    )
    return {
        "sensor": "healthy" if sensor_ok else "unhealthy",
        "sensor_detail": sensor,
        "issues": [label for condition, label in (
            (sensor.get("complete") is not True, "incomplete_sensor_window"),
            (sensor.get("sensor_healthy") is not True, "sensor_unhealthy"),
            (sensor.get("clock_synchronized") is not True, "clock_unsynchronized"),
            (sensor.get("capture_drops") != 0, "capture_drops_or_unavailable"),
            (bool(sensor.get("unavailable_device_ids")), "device_identity_unavailable"),
        ) if condition],
        "complete": sensor.get("complete") is True,
        "joined": bool(joined) and joined.get("partial") is False,
        "gnn": branch.get("gnn", "unavailable" if not gnn else "available"),
        "gnn_detail": gnn.get("health") or {},
        "gnn_fresh": freshness.get("fresh"),
        "gnn_age_seconds": freshness.get("age_seconds"),
        "mud": branch.get("mud", "available" if (mud.get("health") or {}).get("available") else "unavailable"),
        "mud_detail": mud.get("health") or {},
        "partial": joined.get("partial") if joined else None,
    }


def _traces(rows, include_events=True):
    """Join append-only events into complete observation traces."""
    grouped = defaultdict(list)
    decision_to_trace = {}
    for row in rows:
        payload = row.get("payload") or {}
        trace_id = row.get("trace_id")
        if row.get("kind") == "decision" and trace_id:
            decision_to_trace[payload.get("decision_id")] = trace_id
        if not trace_id:
            trace_id = decision_to_trace.get((payload.get("request") or {}).get("decision_id"))
        grouped[trace_id or "unlinked"].append(row)

    result = []
    for trace_id, events in grouped.items():
        window = _payload(events, "window")
        if not window and trace_id == "unlinked":
            continue
        gnn = _payload(events, "gnn_evidence")
        mud = _payload(events, "mud_evidence")
        joined = _payload(events, "joined_evidence")
        decision = _payload(events, "decision")
        outcome = _payload(events, "controller_outcome")
        times = {row["kind"]: row["recorded_at"] for row in events}
        telemetry = window.get("telemetry") or []
        first_flow = min(
            (float(flow["flow_start"]) for flow in telemetry if flow.get("flow_start") is not None),
            default=None,
        )
        installed_at = outcome.get("installed_at")
        mud_counts = Counter(row.get("permission", "unknown") for row in mud.get("exchanges", []))
        devices = gnn.get("devices") or []
        trace = {
            "trace_id": trace_id,
            "run_id": window.get("run_id") or decision.get("run_id"),
            "session_id": window.get("session_id") or decision.get("session_id"),
            "sensor_id": window.get("sensor_id") or decision.get("sensor_id"),
            "inventory_version": window.get("inventory_version") or decision.get("inventory_version"),
            "window_start": window.get("window_start") or decision.get("window_start"),
            "window_end": window.get("window_end") or decision.get("window_end"),
            "observation_kind": window.get("observation_kind") or decision.get("observation_kind"),
            "event_kinds": [row["kind"] for row in events],
            "timestamps": times,
            "health": _trace_health(window, gnn, mud, joined),
            "counts": {
                "flows": len(telemetry),
                "devices": len(devices),
                "active_devices": sum(row.get("status") in ("ok", "active") for row in devices),
                "behavioral_flags": sum(row.get("behavioral_flag") is True for row in devices),
                "link_flags": sum(row.get("link_flag") is True for row in devices),
                "mud_allowed": mud_counts["allowed"],
                "mud_denied": mud_counts["denied"],
                "mud_unknown": mud_counts["unknown_policy"] + mud_counts["unknown_device"],
                "proposals": len(decision.get("proposals") or []),
            },
            "decision": {
                "decision_id": decision.get("decision_id"),
                "mode": decision.get("mode"),
                "policy_version": decision.get("decision_policy_version"),
                "enforcement_eligible": decision.get("enforcement_eligible"),
                "withheld_reasons": decision.get("withheld_reasons") or [],
                "proposals": decision.get("proposals") or [],
            },
            "action": outcome or None,
            "model": gnn.get("model") or {},
            "mud_policy": {"version": mud.get("policy_version"), "hash": mud.get("policy_hash")},
            "latency_seconds": {
                "packet_to_window_close": (
                    window.get("window_end") - first_flow
                    if first_flow is not None and window.get("window_end") is not None else None
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
                    installed_at - times.get("decision")
                    if installed_at is not None and times.get("decision") is not None else None
                ),
                "packet_to_install": (
                    installed_at - first_flow
                    if installed_at is not None and first_flow is not None else None
                ),
            },
        }
        if include_events:
            trace["events"] = events
        result.append(trace)
    return sorted(result, key=lambda row: row["window_start"] or 0, reverse=True)


def _friendly_name(device_id):
    raw = str(device_id or "Unknown device").split("_")[0]
    names = {
        "AmazonEcho": "Amazon Echo", "AugustDoorBell": "August Doorbell",
        "BelkinWemoMotionSensor": "Belkin WeMo Motion Sensor", "BelkinWemoSwitch": "Belkin WeMo Switch",
        "HPPrinter": "HP Printer", "LiFXBulb": "LIFX Bulb", "NestDropCam": "Nest Dropcam",
        "NetatmoWeatherStation": "Netatmo Weather Station", "NetatmoWelcome": "Netatmo Welcome",
        "PhilipsHue": "Philips Hue", "SamsungCamera": "Samsung Camera", "SamsungSmartThings": "Samsung SmartThings",
    }
    if raw in names:
        return names[raw]
    characters = []
    for index, char in enumerate(raw):
        if index and char.isupper() and not raw[index - 1].isupper():
            characters.append(" ")
        characters.append(char)
    return "".join(characters)


def _devices(deployment, traces):
    configured = {row["device_id"]: row for row in deployment["devices"]}
    latest = {}
    last_valid = defaultdict(dict)
    histories = defaultdict(list)
    latest_mud = defaultdict(Counter)
    last_seen = {}
    newest_window = traces[0].get("window_start") if traces else int(time.time())
    for trace in reversed(traces):
        gnn = _payload(trace.get("events") or [], "gnn_evidence")
        for row in gnn.get("devices") or []:
            device_id = row.get("device_id")
            if not device_id:
                continue
            if trace is traces[0]:
                latest[device_id] = row
            for head, score, flag in (("a", "behavioral_score", "behavioral_flag"), ("b", "link_anomaly", "link_flag")):
                if row.get(score) is not None and row.get(flag) is not None:
                    last_valid[device_id][head] = {
                        "score": row[score], "flag": row[flag],
                        "threshold": ((row.get("calibration_scope") or {}).get(head) or {}).get("value"),
                        "window_start": trace.get("window_start"), "run_id": trace.get("run_id"),
                        "session_id": trace.get("session_id"), "trace_id": trace["trace_id"],
                    }
            histories[device_id].append({
                "window_start": trace.get("window_start"),
                "behavioral_score": row.get("behavioral_score"),
                "behavioral_flag": row.get("behavioral_flag"),
                "link_anomaly": row.get("link_anomaly"),
                "link_flag": row.get("link_flag"),
                "status": row.get("status"),
            })
        if trace.get("window_start") == newest_window:
            mud = _payload(trace.get("events") or [], "mud_evidence")
            for exchange in mud.get("exchanges") or []:
                for device_id in (exchange.get("initiator_device_id"), exchange.get("responder_device_id")):
                    if device_id:
                        last_seen[device_id] = exchange.get("observed_at")
                if exchange.get("initiator_device_id"):
                    latest_mud[exchange["initiator_device_id"]][exchange.get("permission", "unknown")] += 1

    output = []
    for device_id, config in configured.items():
        evidence = latest.get(device_id) or {}
        binding = active_binding(deployment, device_id, newest_window) or {}
        a_flag, b_flag = evidence.get("behavioral_flag"), evidence.get("link_flag")
        if a_flag is True or b_flag is True:
            risk = "anomalous"
        elif evidence.get("status") in ("ok", "active") and a_flag is False and b_flag is False:
            risk = "normal"
        elif evidence.get("status") in ("ok", "active"):
            risk = "monitoring"
        else:
            risk = "unscored"
        calibration = evidence.get("calibration_scope") or {}
        output.append({
            "device_id": device_id,
            "name": _friendly_name(device_id),
            "device_type": config.get("device_type"),
            "binding": {"ip": None, "mac": None, "switch_port": None, **binding, "inventory_version": deployment["inventory_version"]},
            "evidence_window": newest_window if traces else None,
            "evidence_run_id": traces[0].get("run_id") if traces else None,
            "last_valid": last_valid[device_id],
            "status": evidence.get("status", "unavailable"),
            "risk": risk,
            "behavioral_score": evidence.get("behavioral_score"),
            "behavioral_flag": a_flag,
            "behavioral_threshold": (calibration.get("a") or {}).get("value"),
            "link_anomaly": evidence.get("link_anomaly"),
            "link_flag": b_flag,
            "link_threshold": (calibration.get("b") or {}).get("value"),
            "unscored_reasons": evidence.get("unscored_reasons") or (
                {} if evidence else {"a": "current_evidence_unavailable", "b": "current_evidence_unavailable"}
            ),
            "history_state": evidence.get("history") or {},
            "profile_support": evidence.get("profile_support") or {},
            "mud": dict(latest_mud[device_id]),
            "last_seen": last_seen.get(device_id),
            "history": histories[device_id][-60:],
        })
    return sorted(output, key=lambda row: (row["risk"] != "anomalous", row["name"]))


def _topology(deployment, traces, device_rows):
    nodes = []
    nodes.extend({
        "id": row["device_id"], "name": row["name"], "type": row["device_type"],
        "status": row["status"], "risk": row["risk"], "ip": row["binding"]["ip"],
    } for row in device_rows)
    known = {row["id"] for row in nodes}
    edges = {}
    for trace in traces[:5]:
        events = trace.get("events") or []
        mud = _payload(events, "mud_evidence")
        window = _payload(events, "window")
        flows = {row.get("uid"): row for row in window.get("telemetry") or []}
        for exchange in mud.get("exchanges") or []:
            source = exchange.get("initiator_device_id") or f"external:{exchange.get('initiator_ip')}"
            target = exchange.get("responder_device_id") or f"external:{exchange.get('responder_ip')}"
            for node_id, label in ((source, exchange.get("initiator_ip")), (target, exchange.get("responder_ip"))):
                if node_id.startswith("external:") and node_id not in known:
                    nodes.append({"id": node_id, "name": label, "type": "external", "status": "observed"})
                    known.add(node_id)
            key = (source, target, exchange.get("proto"), exchange.get("service_port"))
            flow = flows.get(exchange.get("flow_uid")) or {}
            edge = edges.setdefault(key, {
                "source": source, "target": target, "proto": exchange.get("proto"),
                "port": exchange.get("service_port"), "count": 0, "bytes": 0,
                "permissions": Counter(), "last_seen": exchange.get("observed_at"),
            })
            edge["count"] += 1
            edge["bytes"] += int(flow.get("orig_ip_bytes", 0) or 0) + int(flow.get("resp_ip_bytes", 0) or 0)
            edge["permissions"][exchange.get("permission", "unknown")] += 1
            edge["last_seen"] = max(edge["last_seen"] or 0, exchange.get("observed_at") or 0)
    output = []
    for edge in edges.values():
        edge["permissions"] = dict(edge["permissions"])
        output.append(edge)
    output.sort(key=lambda row: (row["permissions"].get("denied", 0), row["count"]), reverse=True)
    return {
        "nodes": nodes, "edges": output, "total_relationships": len(output),
        "total_flows": sum(row["count"] for row in output),
        "window_start": min((row["window_start"] for row in traces[:5] if row.get("window_start") is not None), default=None),
        "window_end": max((row["window_end"] for row in traces[:5] if row.get("window_end") is not None), default=None),
        "run_ids": sorted({row["run_id"] for row in traces[:5] if row.get("run_id")}),
        "session_ids": sorted({row["session_id"] for row in traces[:5] if row.get("session_id")}),
        "kind": "observed_logical_communication", "retained_windows": min(5, len(traces)),
    }


def _explanation(proposal, observation_kind, mode):
    target = _friendly_name(proposal.get("target_device_id"))
    scope = proposal.get("scope") or {}
    service = ""
    if scope:
        service = f" using {str(scope.get('proto', 'network traffic')).upper()} port {scope.get('destination_port', 'unknown')}"
    if proposal.get("reason") == "forbidden_exchange_with_link_anomaly":
        finding = f"{target} made a MUD-denied connection to {scope.get('destination_ip')}{service}, and Head B raised a link-anomaly flag."
    elif proposal.get("reason") == "repeated_forbidden_exchange":
        finding = f"{target} repeatedly made a connection that its MUD policy does not permit."
    elif proposal.get("reason") == "behavioral_anomaly_requires_flow_attribution":
        finding = f"Head A flagged unusual behavior for {target}; the system could not attribute it to one enforceable flow."
    else:
        finding = f"{target} made a connection that its MUD policy does not permit{service}."
    if observation_kind == "engineering" or mode != "enforce":
        return finding + " AutoMUD recorded the proposal only because this run is in safe observation mode."
    if proposal.get("dispatch_eligible"):
        return finding + f" The approved response policy selected a scoped {proposal.get('tier', 'response')} action."
    return finding + " The action was withheld by cooldown, override, binding, or policy state."


def _alerts(traces):
    output, seen = [], set()
    for trace in traces:
        decision = trace.get("decision") or {}
        for proposal in decision.get("proposals") or []:
            identifier = proposal.get("proposal_id") or f"{trace['trace_id']}:{proposal.get('target_device_id')}:{proposal.get('reason')}"
            if identifier in seen:
                continue
            seen.add(identifier)
            output.append({
                "id": identifier, "trace_id": trace["trace_id"], "window_start": trace.get("window_start"),
                "severity": "critical" if proposal.get("tier") == "block" else "warning",
                "category": "security", "title": proposal.get("tier", "alert").replace("_", " ").title(),
                "device_id": proposal.get("target_device_id"),
                "device_name": _friendly_name(proposal.get("target_device_id")),
                "reason": proposal.get("reason"),
                "explanation": _explanation(proposal, trace.get("observation_kind"), decision.get("mode")),
                "state": "installed" if trace.get("action") else "observed",
                "proposal": proposal,
            })
        problems = [reason for reason in decision.get("withheld_reasons") or [] if reason != "engineering_observation"]
        issues = trace.get("health", {}).get("issues") or []
        if "gnn_observation_unhealthy" in problems and issues:
            problems = [reason for reason in problems if reason != "gnn_observation_unhealthy"] + issues
        if trace.get("health", {}).get("partial") is True and "partial_or_unavailable_branch" not in problems:
            problems.append("partial_or_unavailable_branch")
        if problems:
            output.append({
                "id": f"health-{trace['trace_id']}", "trace_id": trace["trace_id"],
                "window_start": trace.get("window_start"), "severity": "warning", "category": "operations",
                "title": "Evidence quality requires attention", "device_id": None, "device_name": "Pipeline",
                "reason": problems[0],
                "explanation": "This observation was not eligible for enforcement: "
                + ", ".join(reason.replace("_", " ") for reason in problems) + ".",
                "state": "withheld",
            })
    grouped = {}
    latest_trace = traces[0]["trace_id"] if traces else None
    for row in output:
        row["current"] = row["trace_id"] == latest_trace
        row["occurrences"] = 1
        row["first_window"] = row["window_start"]
        if row["category"] == "security":
            grouped[row["id"]] = row
            continue
        trace = next(item for item in traces if item["trace_id"] == row["trace_id"])
        key = (trace.get("run_id"), row["explanation"])
        if key in grouped:
            grouped[key]["occurrences"] += 1
            grouped[key]["first_window"] = row["window_start"]
        else:
            grouped[key] = row
    return sorted(grouped.values(), key=lambda row: row.get("window_start") or 0, reverse=True)


def _controller_snapshot(url):
    result = {"available": False, "actions": [], "switches": [], "error": None}
    try:
        for path, key in (("/v1/actions", "actions"), ("/v1/switches", "switches")):
            request = Request(url.rstrip("/") + path, headers={"Accept": "application/json"})
            with urlopen(request, timeout=1.5) as response:
                result[key] = json.loads(response.read()).get(key, [])
        result["available"] = True
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    return result


def _archived_action_events(runtime_root):
    """Read explicit acceptance reports without inventing window/event joins."""
    events = []
    paths = sorted((Path(runtime_root) / "runs").glob("*/controller-action-smoke.json"), reverse=True)[:32]
    for path in paths:
        report = _read_json(path, {})
        if report.get("status") != "passed":
            continue
        outcomes = [report.get(key) for key in ("accepted", "installed", "expired", "revoke_installed", "revoked")]
        outage = report.get("controller_outage") or {}
        if outage.get("installed"):
            # A tested traffic recovery is evidence of effect, not a recorded
            # terminal controller result. Preserve that distinction.
            outcomes.append(outage["installed"])
        for payload in outcomes:
            if isinstance(payload, dict) and payload.get("request"):
                events.append({
                    "kind": "controller_outcome", "payload": payload,
                    "source": "archived_acceptance", "run_id": path.parent.name,
                    "evidence_path": str(path), "traffic_effect": {
                        key: report[key] for key in (
                            "tcp_reachable_before", "tcp_reachable_during", "unaffected_tcp_reachable_during",
                            "tcp_reachable_after_expiry", "tcp_reachable_after_revoke"
                        ) if key in report
                    },
                })
    return events


def _actions(rows, controller, now=None):
    now = time.time() if now is None else now
    indexed = {}
    lifecycle = defaultdict(list)
    for row in rows:
        if row.get("kind") != "controller_outcome":
            continue
        payload = row.get("payload") or {}
        request = payload.get("request") or {}
        decision_id = request.get("decision_id")
        lifecycle[decision_id].append({key: payload.get(key) for key in (
            "status", "accepted_at", "installed_at", "expires_at", "expired_at", "removed_at", "error"
        )})
        indexed[decision_id or row.get("event_id")] = {
            "decision_id": decision_id, "device_id": request.get("device_id"),
            "device_name": _friendly_name(request.get("device_id")), "action": request.get("action"),
            "scope": request.get("scope"), "status": payload.get("status"),
            "accepted_at": payload.get("accepted_at"), "installed_at": payload.get("installed_at"),
            "expires_at": payload.get("expires_at"), "expired_at": payload.get("expired_at"),
            "removed_at": payload.get("removed_at"), "ttl_seconds": request.get("ttl_seconds"),
            "cookie": payload.get("cookie"), "error": payload.get("error"), "source": row.get("source", "event_log"),
            "run_id": row.get("run_id"), "evidence_path": row.get("evidence_path"),
            "traffic_effect": row.get("traffic_effect"),
        }
    for payload in controller.get("actions") or []:
        request = payload.get("request") or {}
        decision_id = request.get("decision_id")
        indexed[decision_id or secrets.token_hex(4)] = {
            "decision_id": decision_id, "device_id": request.get("device_id"),
            "device_name": _friendly_name(request.get("device_id")), "action": request.get("action"),
            "scope": request.get("scope"), "status": payload.get("status"),
            "accepted_at": payload.get("accepted_at"), "installed_at": payload.get("installed_at"),
            "expires_at": payload.get("expires_at"), "expired_at": payload.get("expired_at"),
            "removed_at": payload.get("removed_at"), "ttl_seconds": request.get("ttl_seconds"),
            "cookie": payload.get("cookie"), "error": payload.get("error"), "source": "controller",
        }
    for row in indexed.values():
        row["lifecycle"] = lifecycle[row["decision_id"]]
        if row["source"] == "archived_acceptance" and row.get("status") in ("accepted", "installed"):
            row["status"] = "historical_terminal_unrecorded"
    return sorted(indexed.values(), key=lambda row: row.get("accepted_at") or 0, reverse=True)


def _percentile(values, fraction):
    values = sorted(value for value in values if value is not None)
    if not values:
        return None
    return values[min(len(values) - 1, max(0, round((len(values) - 1) * fraction)))]


def build_dashboard_snapshot(deployment, rows, finalizer=None, controller=None, runtime=None, now=None, archived_actions=None):
    traces = _traces(rows, include_events=True)
    device_rows = _devices(deployment, traces)
    alert_rows = _alerts(traces[:250])
    controller = controller or {"available": False, "actions": [], "switches": [], "error": "not queried"}
    action_rows = _actions((archived_actions or []) + rows, controller, now=now)
    latest = traces[0] if traces else {}
    now = time.time() if now is None else now
    runtime = runtime or {}
    last_observation = latest.get("window_end")
    age = max(0, now - last_observation) if last_observation is not None else None
    fresh = age is not None and age <= deployment["gnn"].get("stale_after_seconds", 180)
    same_run = bool(runtime.get("run_id") and runtime.get("run_id") == latest.get("run_id"))
    runtime_active = runtime.get("active") is True
    current = runtime_active and fresh and same_run
    for alert in alert_rows:
        alert["current"] = alert["current"] and current
    latencies = [row.get("latency_seconds", {}).get("window_close_to_join") for row in traces]
    overview = {
        "schema_version": "automud.dashboard.v2", "generated_at": now,
        "deployment_id": deployment["deployment_id"], "inventory_version": deployment["inventory_version"],
        "observation_kind": deployment["observation_kind"], "decision_mode": deployment["decision"]["mode"],
        "automatic_enforcement_enabled": bool(
            deployment["observation_kind"] == "live" and deployment["decision"]["mode"] == "enforce"
        ),
        "admin_controls_enabled": bool(os.environ.get("AUTOMUD_DASHBOARD_ADMIN_TOKEN")),
        "latest_window": latest.get("window_start"), "latest_health": latest.get("health") or {},
        "last_observation": last_observation, "observation_age_seconds": age,
        "evidence_fresh": fresh, "current_run_evidence": same_run,
        "runtime": {key: runtime.get(key) for key in (
            "active", "run_id", "session_id", "started_at", "stopped_at", "bridge", "sensor_interface", "traffic_kind"
        )},
        "sensor_input": "receiving" if current and (latest.get("health") or {}).get("sensor") == "healthy"
        else "degraded" if current else "awaiting_current_observation" if runtime_active else "stopped",
        "model": latest.get("model") or {}, "mud_policy": latest.get("mud_policy") or {},
        "finalizer": finalizer or {}, "controller": controller,
        "metrics": {
            "devices": len(device_rows), "active_devices": sum(row["status"] in ("ok", "active") for row in device_rows),
            "anomalous_devices": sum(row["risk"] == "anomalous" for row in device_rows),
            "open_security_alerts": sum(row["category"] == "security" and row["current"] for row in alert_rows),
            "active_actions": sum(row.get("status") in ("accepted", "installed", "removing") for row in action_rows),
            "windows": len(traces),
            "healthy_windows": sum(
                row.get("health", {}).get("sensor") == "healthy"
                and row.get("health", {}).get("partial") is not True for row in traces
            ),
            "p50_window_to_join": statistics.median([value for value in latencies if value is not None])
            if any(value is not None for value in latencies) else None,
            "p95_window_to_join": _percentile(latencies, .95),
        },
    }
    return {
        "overview": overview, "devices": device_rows,
        "topology": _topology(deployment, traces, device_rows),
        "alerts": alert_rows, "actions": action_rows,
        "traces": [{key: value for key, value in trace.items() if key != "events"} for trace in traces[:250]],
        "trace_details": {trace["trace_id"]: trace for trace in traces[:250]},
    }


class SnapshotCache:
    def __init__(self, deployment):
        self.deployment = deployment
        self.lock = threading.Lock()
        self.signature = None
        self.value = None

    def get(self):
        event_path = Path(self.deployment["paths"]["event_log"])
        status_path = Path(self.deployment["paths"]["queue"]) / "status.json"
        runtime_path = Path(self.deployment["paths"]["runtime_root"]) / "current.json"
        signature = (
            event_path.stat().st_mtime_ns if event_path.exists() else 0,
            event_path.stat().st_size if event_path.exists() else 0,
            status_path.stat().st_mtime_ns if status_path.exists() else 0,
            runtime_path.stat().st_mtime_ns if runtime_path.exists() else 0,
            int(time.time() // 5),
        )
        with self.lock:
            if self.value is not None and self.signature == signature:
                return self.value
            runtime = _read_json(runtime_path, {})
            if runtime.get("active") and runtime.get("topology_pid"):
                from integration.live.finalizer import _runtime_process_active
                runtime["active"] = _runtime_process_active(runtime)
            self.value = build_dashboard_snapshot(
                self.deployment, _events(event_path, MAX_EVENTS), _read_json(status_path, {}),
                _controller_snapshot(self.deployment["network"]["controller_api"]),
                runtime=runtime,
                archived_actions=_archived_action_events(self.deployment["paths"]["runtime_root"]),
            )
            self.signature = signature
            return self.value

    def invalidate(self):
        with self.lock:
            self.signature = None


def _override_document(path):
    return _read_json(path, {"schema_version": "automud.human-overrides.v1", "overrides": []})


def _write_overrides(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".human-overrides-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, address, deployment, static_root):
        super().__init__(address, DashboardHandler)
        self.deployment = deployment
        self.static_root = Path(static_root).resolve()
        self.snapshots = SnapshotCache(deployment)
        self.override_lock = threading.Lock()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "AutoMUDDashboard/2"

    def log_message(self, fmt, *args):
        return

    def _security_headers(self):
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)

    def _json(self, value, status=200):
        body = json.dumps(value, sort_keys=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        expected = os.environ.get("AUTOMUD_DASHBOARD_ADMIN_TOKEN")
        supplied = self.headers.get("Authorization", "")
        return bool(expected and supplied.startswith("Bearer ") and secrets.compare_digest(supplied[7:], expected))

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("Invalid request body size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("Request body must be an object")
        return value

    def do_GET(self):
        parsed = urlparse(self.path)
        snapshot = self.server.snapshots.get() if parsed.path.startswith("/api/") else None
        if parsed.path == "/api/dashboard":
            self._json({key: value for key, value in snapshot.items() if key != "trace_details"})
            return
        if parsed.path == "/api/status":
            self._json(snapshot["overview"])
            return
        if parsed.path == "/api/devices":
            self._json({"devices": snapshot["devices"]})
            return
        if parsed.path == "/api/topology":
            self._json(snapshot["topology"])
            return
        if parsed.path == "/api/alerts":
            self._json({"alerts": snapshot["alerts"]})
            return
        if parsed.path == "/api/actions":
            self._json({"actions": snapshot["actions"], "controller": snapshot["overview"]["controller"]})
            return
        if parsed.path == "/api/traces":
            limit = max(1, min(int(parse_qs(parsed.query).get("limit", [100])[0]), 250))
            self._json({"traces": snapshot["traces"][:limit]})
            return
        if parsed.path.startswith("/api/traces/"):
            trace_id = unquote(parsed.path[len("/api/traces/"):])
            detail = snapshot["trace_details"].get(trace_id)
            self._json(detail or {"status": "not_found"}, 200 if detail else 404)
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            self._json({"events": _events(
                self.server.deployment["paths"]["event_log"],
                query.get("limit", [200])[0], query.get("kind", [None])[0],
            )})
            return
        if parsed.path == "/api/overrides":
            path = self.server.deployment["decision"].get("override_file")
            document = _override_document(path) if path else {"overrides": []}
            now = time.time()
            self._json({
                "enabled": bool(os.environ.get("AUTOMUD_DASHBOARD_ADMIN_TOKEN") and path),
                "overrides": [row for row in document.get("overrides", []) if float(row.get("expires_at", 0)) > now],
            })
            return
        relative = "index.html" if parsed.path == "/" else parsed.path.lstrip("/")
        target = (self.server.static_root / relative).resolve()
        if self.server.static_root not in target.parents and target != self.server.static_root or not target.is_file():
            self._json({"status": "not_found"}, 404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/overrides":
            self._json({"status": "not_found"}, 404)
            return
        if not self._authorized():
            self._json({"status": "unauthorized", "error": "An enabled dashboard admin token is required"}, 401)
            return
        try:
            value = self._body()
            deployment = self.server.deployment
            path = deployment["decision"].get("override_file")
            if not path:
                raise ValueError("No override store is configured")
            target = value.get("target_device_id")
            if target is not None and target not in {row["device_id"] for row in deployment["devices"]}:
                raise ValueError("Unknown target device")
            actor, reason = str(value.get("actor", "")).strip(), str(value.get("reason", "")).strip()
            expires_at, now = float(value.get("expires_at", 0)), time.time()
            if not 2 <= len(actor) <= 80 or not 5 <= len(reason) <= 300:
                raise ValueError("Actor or reason is missing or too long")
            if expires_at < now + 60 or expires_at > now + 7 * 86400:
                raise ValueError("Override expiry must be between one minute and seven days")
            override = {
                "override_id": "dashboard-" + secrets.token_hex(8), "action": "suppress",
                "actor": actor, "reason": reason, "expires_at": expires_at,
                "target_device_id": target, "created_at": now, "source": "dashboard",
            }
            with self.server.override_lock:
                document = _override_document(path)
                document.setdefault("overrides", []).append(override)
                document.setdefault("audit", []).append({
                    "operation": "create", "recorded_at": now, "actor": actor,
                    "reason": reason, "override": dict(override),
                })
                _write_overrides(path, document)
            self.server.snapshots.invalidate()
            self._json({"status": "created", "override": override}, 201)
        except (ValueError, TypeError, json.JSONDecodeError, OSError) as error:
            self._json({"status": "rejected", "error": str(error)}, 400)

    def do_DELETE(self):
        prefix = "/api/overrides/"
        if not self.path.startswith(prefix):
            self._json({"status": "not_found"}, 404)
            return
        if not self._authorized():
            self._json({"status": "unauthorized", "error": "An enabled dashboard admin token is required"}, 401)
            return
        try:
            path = self.server.deployment["decision"].get("override_file")
            if not path:
                raise ValueError("No override store is configured")
            override_id = unquote(self.path[len(prefix):])
            value = self._body()
            actor, reason = str(value.get("actor", "")).strip(), str(value.get("reason", "")).strip()
            if not 2 <= len(actor) <= 80 or not 5 <= len(reason) <= 300:
                raise ValueError("Removal requires an operator name and reason")
            with self.server.override_lock:
                document = _override_document(path)
                removed = next((row for row in document.get("overrides", []) if row.get("override_id") == override_id), None)
                if removed is None:
                    self._json({"status": "not_found"}, 404)
                    return
                document["overrides"] = [row for row in document.get("overrides", []) if row.get("override_id") != override_id]
                document.setdefault("audit", []).append({
                    "operation": "remove", "recorded_at": time.time(), "actor": actor,
                    "reason": reason, "override": dict(removed),
                })
                _write_overrides(path, document)
            self.server.snapshots.invalidate()
            self._json({"status": "removed", "override_id": override_id})
        except (ValueError, OSError) as error:
            self._json({"status": "rejected", "error": str(error)}, 400)


def main():
    parser = argparse.ArgumentParser(description="AutoMUD live operations dashboard")
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

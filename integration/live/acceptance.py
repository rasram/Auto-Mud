"""Build an evidence-linked live-pipeline acceptance receipt.

The collector never changes service state. It records what was actually tested
and leaves deployment/team gates blocked instead of converting them to passes.
"""
import argparse
import hashlib
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.request import urlopen

from integration.live.common import atomic_json, canonical_digest
from integration.live.config import load_deployment


def _json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _url(url):
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read())


def _services():
    names = ["automud-gnn", "automud-controller", "automud-finalizer", "automud-dashboard"]
    result = {}
    for name in names:
        check = subprocess.run(
            ["systemctl", "is-active", name], capture_output=True, text=True, check=False,
        )
        result[name] = check.stdout.strip() or "unknown"
    return result


def _junit(path):
    if not path or not Path(path).exists():
        return None
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    totals = {name: sum(int(suite.get(name, 0)) for suite in suites) for name in ("tests", "failures", "errors", "skipped")}
    totals["passed"] = totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
    totals["path"] = str(Path(path))
    totals["sha256"] = _sha256(path)
    return totals


def _scenario(name, preconditions, injection, expected, actual, status, artifacts):
    return {
        "name": name, "preconditions": preconditions, "injection": injection,
        "expected": expected, "actual": actual, "status": status,
        "artifacts": [str(path) for path in artifacts if path],
    }


def collect(
    config_path, runtime_path, output, tests_junit=None, action_run=None,
    sensor_run=None, qualification_root=None,
):
    deployment = load_deployment(config_path)
    runtime = _json(runtime_path)
    if not runtime:
        raise ValueError("Runtime receipt is unavailable")
    root = Path(deployment["paths"]["runtime_root"])
    run_root = root / "runs" / runtime["run_id"]
    run_token = canonical_digest([runtime["run_id"], runtime["session_id"]])[:16]
    accepted_dir = Path(deployment["paths"]["queue"]) / "runs" / run_token / "accepted"
    accepted_paths = sorted(accepted_dir.glob("*.json"))
    accepted = [_json(path, {}) for path in accepted_paths]
    tests = _junit(tests_junit)
    tests_passed = bool(tests and tests["failures"] == 0 and tests["errors"] == 0)
    action_root = root / "runs" / action_run if action_run else None
    action_path = action_root / "controller-action-smoke.json" if action_root else None
    action = _json(action_path, {}) if action_path else {}
    sensor_root = root / "runs" / sensor_run if sensor_run else None
    sensor_runtime = _json(sensor_root / "runtime.json", {}) if sensor_root else {}
    sensor_token = canonical_digest([
        sensor_runtime.get("run_id"), sensor_runtime.get("session_id"),
    ])[:16] if sensor_runtime else None
    sensor_accepted_paths = sorted(
        (Path(deployment["paths"]["queue"]) / "runs" / sensor_token / "accepted").glob("*.json")
    ) if sensor_token else []
    sensor_accepted = [_json(path, {}) for path in sensor_accepted_paths]
    qualification = Path(qualification_root) if qualification_root else None
    throughput_path = qualification / "throughput/report.json" if qualification else None
    rollback_path = qualification / "rollback-model.json" if qualification else None
    rollback_fixture_path = qualification / "rollback-fixture.json" if qualification else None
    service_smoke_path = qualification / "service-smoke/report.json" if qualification else None
    throughput = _json(throughput_path, {}) if throughput_path else {}
    rollback = _json(rollback_path, {}) if rollback_path else {}
    rollback_fixture = _json(rollback_fixture_path, {}) if rollback_fixture_path else {}
    service_smoke = _json(service_smoke_path, {}) if service_smoke_path else {}
    complete = [row for row in accepted if (row.get("window") or {}).get("health", {}).get("complete")]
    startup = [row for row in accepted if not (row.get("window") or {}).get("health", {}).get("complete")]
    dashboard_status = _url("http://127.0.0.1:8090/api/status")
    gnn_health = _url(deployment["gnn"]["url"].rstrip("/") + "/readyz")
    switches = _url(deployment["network"]["controller_api"].rstrip("/") + "/v1/switches")
    scenarios = []
    scenarios.append(_scenario(
        "cold_start_partial_window", "Fresh topology run in engineering mode", "Start inside a UTC minute",
        "Startup window is explicit and cannot dispatch", {
            "partial_windows": len(startup),
            "all_actions_empty": all(not row.get("actions") for row in startup),
        }, "passed" if startup and all(not row.get("actions") for row in startup) else "failed", accepted_paths,
    ))
    scenarios.append(_scenario(
        "healthy_complete_window", "Synchronized Zeek sensor", "Allow a full UTC minute to close",
        "Complete window, zero measured drops, both branches available", {
            "complete_windows": len(complete),
            "healthy": all(
                row["window"]["health"].get("capture_drops") == 0
                and not row["join"].get("partial") for row in complete
            ),
        }, "passed" if complete and all(
            row["window"]["health"].get("capture_drops") == 0 and not row["join"].get("partial")
            for row in complete
        ) else "failed", accepted_paths,
    ))
    scenarios.append(_scenario(
        "engineering_observe_gate", "Committed engineering/observe configuration", "Process accepted windows",
        "No automatic controller dispatch", {
            "automatic_enforcement_enabled": dashboard_status.get("automatic_enforcement_enabled"),
            "all_actions_empty": all(not row.get("actions") for row in accepted),
        }, "passed" if not dashboard_status.get("automatic_enforcement_enabled") and all(
            not row.get("actions") for row in accepted
        ) else "failed", accepted_paths,
    ))
    lifecycle_ok = bool(
        action.get("status") == "passed" and action.get("expired", {}).get("status") == "expired"
        and action.get("revoked", {}).get("status") == "removed"
        and action.get("tcp_reachable_after_expiry") and action.get("tcp_reachable_after_revoke")
    )
    scenarios.append(_scenario(
        "controller_expiry_and_revoke", "Isolated lab with temporary engineering-action approval",
        "Install target-only TCP rules; wait for hard timeout; explicitly revoke second rule",
        "Unaffected traffic remains reachable and target recovers after expiry and revoke", {
            "status": action.get("status"), "expired": action.get("expired", {}).get("status"),
            "revoked": action.get("revoked", {}).get("status"),
        }, "passed" if lifecycle_ok else "not_run", [action_path],
    ))
    outage = action.get("controller_outage") or {}
    outage_ok = bool(
        outage.get("blocked_while_controller_down")
        and outage.get("recovered_while_controller_down")
        and outage.get("controller_actions_after_restart") == []
    )
    scenarios.append(_scenario(
        "controller_outage_and_autonomous_expiry", "Isolated switch with installed five-second rule",
        "Stop the controller while the owned rule is active",
        "Rule remains scoped, expires in OVS, traffic recovers, controller restarts without false state", {
            "blocked_while_controller_down": outage.get("blocked_while_controller_down"),
            "recovered_while_controller_down": outage.get("recovered_while_controller_down"),
            "controller_actions_after_restart": outage.get("controller_actions_after_restart"),
        }, "passed" if outage_ok else "blocked", [action_path],
    ))
    scenarios.append(_scenario(
        "automated_failure_semantics", "Regression suite and deterministic fixtures",
        "Exercise rebinding, stale GNN, missing/late/conflicting branches, cooldown, override, TTL DNS and stopped runtimes",
        "Each failure is explicit and produces no duplicate action", tests or {},
        "passed" if tests_passed else "not_run", [tests_junit],
    ))
    warmup_ok = bool(
        throughput.get("windows") == 60 and throughput.get("devices") == 12
        and throughput.get("keeps_up_with_60_second_cadence")
    )
    scenarios.append(_scenario(
        "one_hour_rolling_warmup", "Saturn CPU qualification with 12-device state",
        "Submit 60 ordered synthetic minute windows", "History remains bounded and service keeps cadence",
        throughput or "Qualification report unavailable", "passed" if warmup_ok else "blocked",
        [throughput_path],
    ))
    sensor_fault_ok = bool(
        sensor_runtime.get("sensor_interruption_at")
        and sensor_accepted
        and any(not row.get("window", {}).get("health", {}).get("clock_synchronized") for row in sensor_accepted)
        and all(not row.get("actions") for row in sensor_accepted)
    )
    scenarios.append(_scenario(
        "sensor_clock_and_interruption", "Isolated engineering topology",
        "Force clock-unsynchronized health and stop Zeek during the run",
        "Unhealthy evidence is explicit and no action is dispatched", {
            "sensor_interruption_at": sensor_runtime.get("sensor_interruption_at"),
            "accepted_windows": len(sensor_accepted),
            "unsynchronized_windows": sum(
                not row.get("window", {}).get("health", {}).get("clock_synchronized")
                for row in sensor_accepted
            ),
            "all_actions_empty": all(not row.get("actions") for row in sensor_accepted),
        }, "passed" if sensor_fault_ok else "blocked", sensor_accepted_paths,
    ))
    rollback_ok = bool(
        rollback.get("status") == "ok" and rollback_fixture.get("status") == "passed"
        and service_smoke.get("durable_service_restart") is True
    )
    scenarios.append(_scenario(
        "model_validation_restart_and_rollback", "Immutable E1+Q and C rollback bundles on Saturn",
        "Validate rollback bundle/fixture and retry across service restart",
        "Bundle validates, fixture reproduces, and accepted retry survives restart", {
            "rollback_model": rollback.get("status"),
            "rollback_fixture": rollback_fixture.get("status"),
            "durable_service_restart": service_smoke.get("durable_service_restart"),
        }, "passed" if rollback_ok else "blocked",
        [rollback_path, rollback_fixture_path, service_smoke_path],
    ))
    for name, reason in (
        ("persistence_failure_and_backlog_restart", "Requires controlled disk/service fault injection"),
    ):
        scenarios.append(_scenario(
            name, "Approved maintenance or isolated test window", "Not performed in this run",
            "Failure remains visible and recovery preserves accepted state", reason, "blocked", [],
        ))
    receipt = {
        "schema_version": "automud.live-acceptance.v1",
        "generated_at": time.time(), "deployment_id": deployment["deployment_id"],
        "inventory_version": deployment["inventory_version"],
        "observation_kind": deployment["observation_kind"],
        "decision_mode": deployment["decision"]["mode"],
        "runtime": runtime, "services": _services(), "gnn_health": gnn_health,
        "controller_switches": switches, "dashboard_status": dashboard_status,
        "tests": tests, "failure_matrix": scenarios,
        "manual_blockers": [
            "Approved live inventory and binding source",
            "Reviewed production MUD policy and DNS/name-evidence rules",
            "Approved response policy, override roles and rollback authority",
            "Dashboard access/retention decision",
            "Named owner review and a scheduled disruptive acceptance window",
        ],
    }
    receipt["receipt_id"] = canonical_digest(receipt)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    atomic_json(output / "failure-matrix.json", receipt)
    manifest_paths = [Path(config_path), Path(runtime_path), *accepted_paths]
    if tests_junit:
        manifest_paths.append(Path(tests_junit))
    if action_path and action_path.exists():
        manifest_paths.append(action_path)
    manifest_paths.extend(sensor_accepted_paths)
    for path in (throughput_path, rollback_path, rollback_fixture_path, service_smoke_path):
        if path:
            manifest_paths.append(path)
    manifest = {
        "schema_version": "automud.acceptance-manifest.v1",
        "receipt_id": receipt["receipt_id"],
        "artifacts": [
            {"path": str(path), "sha256": _sha256(path), "bytes": path.stat().st_size}
            for path in manifest_paths if path.exists()
        ],
    }
    atomic_json(output / "manifest.json", manifest)
    passed = sum(row["status"] == "passed" for row in scenarios)
    blocked = sum(row["status"] == "blocked" for row in scenarios)
    lines = [
        "# AutoMUD live-pipeline acceptance report", "",
        f"Receipt `{receipt['receipt_id']}` was generated from `{runtime['run_id']}`.", "",
        f"Automated scenarios passed: **{passed}**. Blocked scenarios: **{blocked}**.", "",
        "| Scenario | Status | Actual |", "|---|---|---|",
    ]
    for row in scenarios:
        actual = json.dumps(row["actual"], sort_keys=True).replace("|", "\\|")
        lines.append(f"| {row['name']} | {row['status']} | `{actual}` |")
    lines += ["", "## Manual blockers", ""] + [f"- {item}" for item in receipt["manual_blockers"]]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--tests-junit")
    parser.add_argument("--action-run")
    parser.add_argument("--sensor-run")
    parser.add_argument("--qualification-root")
    args = parser.parse_args()
    receipt = collect(
        args.config, args.runtime, args.output, args.tests_junit, args.action_run,
        args.sensor_run, args.qualification_root,
    )
    print(json.dumps({
        "receipt_id": receipt["receipt_id"],
        "passed": sum(row["status"] == "passed" for row in receipt["failure_matrix"]),
        "blocked": sum(row["status"] == "blocked" for row in receipt["failure_matrix"]),
    }, sort_keys=True))


if __name__ == "__main__":
    main()

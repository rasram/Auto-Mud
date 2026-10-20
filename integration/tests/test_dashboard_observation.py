import copy

from integration.live.config import load_deployment
from integration.live.dashboard import _dashboard_payload, build_dashboard_snapshot
from integration.tests.test_live_pipeline import CONFIG, flow, gnn_evidence, window
from integration.live.mud import MUDEngine
from network.testbed.live_probe import probe_plan
import pytest


def records(start=60, run="run-1", complete=True, score=1.2):
    observed = window([flow("known", "10.0.0.11", "10.0.0.20", 8080)])
    observed.update(window_start=start, window_end=start + 60, run_id=run)
    observed["health"]["complete"] = complete
    gnn = gnn_evidence(observed)
    gnn["devices"][0].update({
        "status": "ok" if score is not None else "unavailable",
        "behavioral_score": score, "behavioral_flag": score is not None,
        "link_anomaly": score, "link_flag": False if score is not None else None,
        "unscored_reasons": {} if score is not None else {"a": "incomplete_observation"},
    })
    mud = MUDEngine(load_deployment(CONFIG), now=lambda: start + 65).evaluate(observed)
    decision = {"withheld_reasons": [] if complete else ["gnn_observation_unhealthy"]}
    return [{"kind": kind, "payload": payload, "trace_id": f"{run}-{start}", "recorded_at": start + 65}
            for kind, payload in (("window", observed), ("gnn_evidence", gnn), ("mud_evidence", mud),
                                  ("joined_evidence", {"partial": False, "branch_status": {"gnn": "available", "mud": "available"}}),
                                  ("decision", decision))]


def test_stopped_and_stale_runtime_are_explicit():
    deployment = load_deployment(CONFIG)
    snapshot = build_dashboard_snapshot(deployment, records(), runtime={"active": False, "run_id": "run-1"}, now=1000)
    overview = snapshot["overview"]
    assert overview["runtime"]["active"] is False
    assert overview["last_observation"] == 120
    assert overview["observation_age_seconds"] == 880
    assert overview["evidence_fresh"] is False
    assert overview["sensor_input"] == "stopped"
    assert overview["metrics"]["active_devices"] == 1
    assert snapshot["traces"][0]["counts"]["active_devices"] == 1


def test_new_run_cannot_claim_previous_run_evidence():
    snapshot = build_dashboard_snapshot(load_deployment(CONFIG), records(), runtime={"active": True, "run_id": "new"}, now=125)
    assert snapshot["overview"]["evidence_fresh"]
    assert snapshot["overview"]["current_run_evidence"] is False
    assert snapshot["overview"]["sensor_input"] == "awaiting_current_observation"


def test_available_incomplete_branch_remains_degraded_and_keeps_last_valid():
    rows = records() + records(start=120, complete=False, score=None)
    snapshot = build_dashboard_snapshot(load_deployment(CONFIG), rows, runtime={"active": True, "run_id": "run-1"}, now=185)
    health = snapshot["overview"]["latest_health"]
    assert health["gnn"] == "available"
    assert health["complete"] is False
    assert health["joined"] is True
    assert health["issues"] == ["incomplete_sensor_window"]
    device = next(row for row in snapshot["devices"] if row["device_id"].startswith("AmazonEcho"))
    assert device["behavioral_score"] is None
    assert device["last_valid"]["a"]["score"] == 1.2
    assert device["last_valid"]["a"]["window_start"] == 60
    assert "incomplete sensor window" in snapshot["alerts"][0]["explanation"]


def test_missing_device_in_newest_window_does_not_reuse_old_current_score():
    newer = records(start=120)
    newer[1]["payload"]["devices"] = []
    snapshot = build_dashboard_snapshot(load_deployment(CONFIG), records() + newer)
    device = next(row for row in snapshot["devices"] if row["device_id"].startswith("AmazonEcho"))
    assert device["behavioral_score"] is None
    assert device["last_valid"]["a"]["score"] == 1.2
    assert device["unscored_reasons"]["a"] == "current_evidence_unavailable"


def test_unknown_relationship_survives_more_than_120_denied_edges():
    rows = records()
    mud = rows[2]["payload"]
    denied = copy.deepcopy(mud["exchanges"][0])
    mud["exchanges"] = [dict(denied, service_port=port, permission="denied") for port in range(130)]
    unknown = dict(denied, service_port=9999, permission="unknown_policy")
    mud["exchanges"].extend([unknown, dict(unknown, permission="allowed")])
    topology = build_dashboard_snapshot(load_deployment(CONFIG), rows)["topology"]
    assert len(topology["edges"]) == 131
    mixed = next(edge for edge in topology["edges"] if edge["port"] == 9999)
    assert mixed["permissions"] == {"unknown_policy": 1, "allowed": 1}
    assert topology["total_flows"] == 132
    assert topology["run_ids"] == ["run-1"]
    assert topology["window_end"] == 120


def test_repeated_health_alerts_group_without_losing_time_range():
    rows = records(complete=False, score=None) + records(start=120, complete=False, score=None)
    snapshot = build_dashboard_snapshot(load_deployment(CONFIG), rows, runtime={"active": True, "run_id": "run-1"}, now=185)
    assert len(snapshot["alerts"]) == 1
    alert = snapshot["alerts"][0]
    assert alert["current"]
    assert alert["occurrences"] == 2
    assert (alert["first_window"], alert["window_start"]) == (60, 120)
    stopped = build_dashboard_snapshot(load_deployment(CONFIG), rows, now=1000)
    assert stopped["alerts"][0]["current"] is False


def test_operations_alerts_survive_more_than_200_security_findings():
    older = records(complete=False, score=None)
    newer = records(start=120)
    newer[-1]["payload"]["proposals"] = [
        {"proposal_id": str(index), "target_device_id": "echo", "tier": "alert", "reason": "forbidden_exchange"}
        for index in range(210)
    ]
    alerts = build_dashboard_snapshot(load_deployment(CONFIG), older + newer)["alerts"]
    assert len(alerts) == 211
    assert any(row["category"] == "operations" for row in alerts)


def test_initial_dashboard_payload_is_bounded_without_losing_current_findings():
    older = records(complete=False, score=None)
    newer = records(start=120)
    newer[-1]["payload"]["proposals"] = [
        {
            "proposal_id": str(index), "target_device_id": "echo", "tier": "alert",
            "reason": "forbidden_exchange", "diagnostic": "x" * 2000,
        }
        for index in range(600)
    ]
    snapshot = build_dashboard_snapshot(
        load_deployment(CONFIG), older + newer,
        runtime={"active": True, "run_id": "run-1"}, now=185,
    )
    payload = _dashboard_payload(snapshot)
    assert len(payload["alerts"]) == 600
    assert all(row["current"] for row in payload["alerts"])
    assert "proposals" not in payload["traces"][0]["decision"]
    assert len(snapshot["trace_details"]["run-1-120"]["decision"]["proposals"]) == 600


def test_probe_plan_uses_existing_lab_permissions_and_all_twelve_devices():
    deployment = load_deployment(CONFIG)
    plan = probe_plan(deployment)
    assert len(plan) == 12
    assert sum(len(targets) for targets in plan.values()) == 18
    for targets in plan.values():
        assert any(port == 18080 for _, port in targets)
        assert all(address.startswith("10.0.0.") for address, _ in targets)
    deployment["decision"]["mode"] = "enforce"
    with pytest.raises(ValueError, match="engineering / observe"):
        probe_plan(deployment)


def test_archived_acceptance_actions_preserve_lifecycle_without_claiming_live_install(tmp_path):
    import json
    from integration.live.dashboard import _archived_action_events, _actions
    root = tmp_path / "runs" / "run-archive"
    root.mkdir(parents=True)
    accepted = {"request": {"decision_id": "action-1", "device_id": "echo", "action": "block"},
                "status": "accepted", "accepted_at": 10, "expires_at": 15}
    installed = dict(accepted, status="installed", installed_at=11)
    expired = dict(installed, status="expired", expired_at=16)
    path = root / "controller-action-smoke.json"
    path.write_text(json.dumps({"status": "passed", "accepted": accepted, "installed": installed, "expired": expired}))
    rows = _archived_action_events(tmp_path)
    actions = _actions(rows, {"actions": []}, now=20)
    assert len(actions) == 1
    assert actions[0]["status"] == "expired"
    assert [row["status"] for row in actions[0]["lifecycle"]] == ["accepted", "installed", "expired"]
    assert actions[0]["source"] == "archived_acceptance"
    assert actions[0]["run_id"] == "run-archive"
    path.write_text(json.dumps({"status": "passed", "installed": installed}))
    actions = _actions(_archived_action_events(tmp_path), {"actions": []}, now=20)
    assert actions[0]["status"] == "historical_terminal_unrecorded"


@pytest.mark.parametrize("scope", [None, "AmazonEcho_44650d56ccd3_flows"])
def test_suppression_api_auth_expiry_restart_and_removal_audit(tmp_path, monkeypatch, scope):
    import json
    import threading
    from types import SimpleNamespace
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
    from integration.live import dashboard

    deployment = load_deployment(CONFIG)
    ledger = tmp_path / "overrides.json"
    deployment["decision"]["override_file"] = str(ledger)
    clock = [1000.0]
    monkeypatch.setattr(dashboard.time, "time", lambda: clock[0])
    monkeypatch.setenv("AUTOMUD_DASHBOARD_ADMIN_TOKEN", "test-only-token")

    def start():
        server = dashboard.DashboardServer(("127.0.0.1", 0), deployment, tmp_path)
        server.snapshots = SimpleNamespace(get=lambda: {}, invalidate=lambda: None)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    server, thread = start()

    def request(method, path, body=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        value = Request(f"http://127.0.0.1:{server.server_port}" + path,
                        data=json.dumps(body).encode() if body is not None else None,
                        headers=headers, method=method)
        try:
            response = urlopen(value, timeout=3)
        except HTTPError as error:
            response = error
        with response:
            return response.code, json.loads(response.read())

    value = {"actor": "Test operator", "reason": "Isolated API acceptance", "expires_at": 1100,
             "target_device_id": scope}
    try:
        assert request("POST", "/api/overrides", value)[0] == 401
        assert request("POST", "/api/overrides", value, "wrong")[0] == 401
        assert not ledger.exists()
        assert request("POST", "/api/overrides", dict(value, expires_at=1059), "test-only-token")[0] == 400
        status, created = request("POST", "/api/overrides", value, "test-only-token")
        assert status == 201
        identifier = created["override"]["override_id"]
        assert json.loads(ledger.read_text())["audit"][0]["operation"] == "create"
        server.shutdown()
        server.server_close()
        thread.join()
        server, thread = start()
        assert request("GET", "/api/overrides")[1]["overrides"][0]["override_id"] == identifier
        clock[0] = 1101
        assert request("GET", "/api/overrides")[1]["overrides"] == []
        assert len(json.loads(ledger.read_text())["audit"]) == 1
        clock[0] = 1000
        before = ledger.read_bytes()
        assert request("DELETE", "/api/overrides/" + identifier, token="test-only-token")[0] == 400
        assert ledger.read_bytes() == before
        assert request("DELETE", "/api/overrides/" + identifier, {"actor": "Reviewer", "reason": "Acceptance complete"}, "test-only-token")[0] == 200
        document = json.loads(ledger.read_text())
        assert document["overrides"] == []
        assert [row["operation"] for row in document["audit"]] == ["create", "remove"]
        assert document["audit"][1]["actor"] == "Reviewer"
        assert document["audit"][1]["override"]["override_id"] == identifier
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

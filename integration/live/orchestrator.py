import argparse
import json
import time
from pathlib import Path

from integration.live.config import load_deployment
from integration.live.coordinator import JoinCoordinator, observation_key
from integration.live.controller_client import ControllerClient
from integration.live.decision import DecisionEngine
from integration.live.events import EventStore
from integration.live.gnn import GNNEvidenceClient
from integration.live.mud import MUDEngine, unavailable_mud
from ml.live.contracts import validate_window


class Orchestrator:
    def __init__(self, deployment, now=time.time):
        self.deployment = deployment
        self.now = now
        self.events = EventStore(deployment["paths"]["event_log"])
        self.mud = MUDEngine(deployment, now=now)
        self.gnn = GNNEvidenceClient(deployment, now=now)
        state_db = deployment["paths"].get(
            "state_db", str(Path(deployment["paths"]["queue"]) / "live-state.sqlite3"),
        )
        self.coordinator = JoinCoordinator(
            state_db, join_timeout_seconds=deployment["decision"].get("join_timeout_seconds", 10), now=now,
        )
        self.decisions = DecisionEngine(deployment, now=now)
        self.controller = ControllerClient(deployment["network"]["controller_api"])

    def process(self, raw_window, name_evidence=None):
        window = validate_window(raw_window, now=self.now())
        key = self.coordinator.ingest_window(window)
        self.events.append("window", window)
        mud = None
        try:
            mud = self.mud.evaluate(window, name_evidence=name_evidence)
        except Exception as error:
            mud = unavailable_mud(
                window, self.mud.policy["policy_version"], error,
                now=self.now, policy_hash=self.mud.policy_hash,
            )
        self.events.append("mud_evidence", mud)
        self.coordinator.ingest_branch(key, "mud", mud)
        gnn = None
        gnn_error = None
        try:
            gnn = self.gnn.submit(window)
            self.events.append("gnn_evidence", gnn)
            self.coordinator.ingest_branch(key, "gnn", gnn)
        except Exception as error:
            gnn_error = f"{type(error).__name__}: {error}"
            self.events.append("gnn_unavailable", {"window_start": window["window_start"], "error": gnn_error})
        joined = self.coordinator.close(key)
        if joined is None:
            return {
                "status": "awaiting_join", "observation_key": key,
                "deadline_seconds": self.deployment["decision"].get("join_timeout_seconds", 10),
                "window": window, "mud": mud, "gnn": gnn,
                "gnn_error": gnn_error, "join": None, "decision": None, "actions": [],
            }
        result = self._complete_join(key, joined, gnn_error=gnn_error)
        result.update({"window": window, "mud": mud, "gnn": gnn})
        return result

    def process_due(self):
        results = []
        for joined in self.coordinator.close_ready():
            results.append(self._complete_join(observation_key(joined), joined))
        return results

    def _complete_join(self, key, joined, gnn_error=None):
        self.events.append("joined_evidence", joined)
        existing = self.coordinator.decision_for(key)
        if existing is not None:
            return {
                "status": "complete", "observation_key": key, "join": joined,
                "decision": existing, "actions": self.coordinator.action_outcomes(existing["decision_id"]),
            }
        decision = self.decisions.decide(joined)
        if gnn_error and "gnn_request_failed" not in decision["withheld_reasons"]:
            decision["withheld_reasons"].append("gnn_request_failed")
        self.coordinator.reserve_decision(key, decision)
        self.events.append("decision", decision)
        outcomes = []
        if decision["enforcement_eligible"]:
            for proposal in decision["proposals"]:
                if proposal["tier"] not in ("block", "rate_limit") or not proposal.get("dispatch_eligible"):
                    continue
                request = self._action_request(decision, proposal)
                if not self.coordinator.reserve_action(
                    decision["decision_id"], proposal["proposal_id"], request,
                ):
                    continue
                try:
                    outcome = self.controller.install(request)
                except Exception as error:
                    outcome = {"status": "transport_error", "error": f"{type(error).__name__}: {error}", "request": request}
                outcomes.append(outcome)
                self.coordinator.record_action_outcome(
                    decision["decision_id"], proposal["proposal_id"], outcome,
                )
                self.events.append("controller_outcome", outcome)
        return {
            "status": "complete", "observation_key": key,
            "join": joined, "decision": decision, "actions": outcomes,
        }

    def _action_request(self, decision, proposal):
        binding = proposal["binding"]
        return {
            "schema_version": "automud.action-request.v1",
            "decision_id": decision["decision_id"],
            "proposal_id": proposal["proposal_id"],
            "evidence_id": proposal.get("mud_evidence_id"),
            "observation_kind": decision["observation_kind"],
            "inventory_version": decision["inventory_version"],
            "window_end": decision["window_end"],
            "dpid": self.deployment["network"]["dpid"],
            "device_id": proposal["target_device_id"],
            "device_mac": binding["mac"],
            "device_ip": binding["ip"],
            "switch_port": binding["switch_port"],
            "action": proposal["tier"],
            "scope": proposal["scope"],
            "priority": 40000,
            "ttl_seconds": self.deployment["decision"]["action_ttl_seconds"],
            "reason": proposal["reason"],
        }


def main():
    parser = argparse.ArgumentParser(description="Process one completed AutoMUD live window")
    parser.add_argument("--config", default="configs/live/saturn.json")
    parser.add_argument("--window", required=True)
    args = parser.parse_args()
    deployment = load_deployment(args.config)
    with open(args.window, encoding="utf-8") as handle:
        window = json.load(handle)
    print(json.dumps(Orchestrator(deployment).process(window), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

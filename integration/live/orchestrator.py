import argparse
import json
import os
import time

from integration.live.config import load_deployment
from integration.live.controller_client import ControllerClient
from integration.live.decision import DecisionEngine
from integration.live.events import EventStore
from integration.live.join import join_evidence
from integration.live.mud import MUDEngine, unavailable_mud
from ml.live.client import Client
from ml.live.contracts import validate_window


class Orchestrator:
    def __init__(self, deployment, now=time.time):
        self.deployment = deployment
        self.now = now
        self.events = EventStore(deployment["paths"]["event_log"])
        self.mud = MUDEngine(deployment, now=now)
        gnn = deployment["gnn"]
        self.gnn = Client(
            url=gnn["url"], token=os.environ.get("AUTOMUD_GNN_API_TOKEN"),
            timeout=gnn.get("timeout_seconds", 30), retries=2,
        )
        self.decisions = DecisionEngine(deployment, now=now)
        self.controller = ControllerClient(deployment["network"]["controller_api"])

    def process(self, raw_window):
        window = validate_window(raw_window, now=self.now())
        self.events.append("window", window)
        mud = None
        try:
            mud = self.mud.evaluate(window)
        except Exception as error:
            mud = unavailable_mud(window, self.mud.policy["policy_version"], error, now=self.now)
        self.events.append("mud_evidence", mud)
        gnn = None
        gnn_error = None
        try:
            gnn = self.gnn.submit(window)
            self.events.append("gnn_evidence", gnn)
        except Exception as error:
            gnn_error = f"{type(error).__name__}: {error}"
            self.events.append("gnn_unavailable", {"window_start": window["window_start"], "error": gnn_error})
        joined = join_evidence(window, gnn=gnn, mud=mud, now=self.now)
        self.events.append("joined_evidence", joined)
        decision = self.decisions.decide(joined)
        if gnn_error:
            decision["withheld_reasons"].append("gnn_request_failed")
        self.events.append("decision", decision)
        outcomes = []
        if decision["enforcement_eligible"]:
            for proposal in decision["proposals"]:
                if proposal["tier"] not in ("block", "rate_limit"):
                    continue
                request = self._action_request(decision, proposal)
                try:
                    outcome = self.controller.install(request)
                except Exception as error:
                    outcome = {"status": "transport_error", "error": f"{type(error).__name__}: {error}", "request": request}
                outcomes.append(outcome)
                self.events.append("controller_outcome", outcome)
        return {"window": window, "mud": mud, "gnn": gnn, "join": joined, "decision": decision, "actions": outcomes}

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

import time

from integration.live.common import canonical_digest
from integration.live.config import bindings


class DecisionEngine:
    def __init__(self, deployment, now=time.time):
        self.deployment = deployment
        self.now = now
        self.by_ip, self.by_id = bindings(deployment)

    def decide(self, joined):
        proposals = []
        reasons = []
        gnn = joined.get("gnn_evidence")
        mud = joined.get("mud_evidence")
        gnn_devices = {row["device_id"]: row for row in (gnn or {}).get("devices", [])}
        if joined["partial"]:
            reasons.append("partial_or_unavailable_branch")
        elif gnn and not _gnn_healthy(gnn):
            reasons.append("gnn_observation_unhealthy")
        else:
            for exchange in (mud or {}).get("exchanges", []):
                if exchange["permission"] != "denied":
                    continue
                device_id = exchange["initiator_device_id"]
                score = gnn_devices.get(device_id, {})
                link_flag = score.get("link_flag") is True
                tier = "block" if link_flag else "alert"
                device = self.by_id.get(device_id)
                proposal = {
                    "tier": tier,
                    "target_device_id": device_id,
                    "binding": {"mac": device["mac"], "ip": device["ip"]} if device else None,
                    "scope": {
                        "proto": exchange["proto"],
                        "destination_ip": exchange["responder_ip"],
                        "destination_port": exchange["service_port"],
                    },
                    "mud_evidence_id": mud["evidence_id"],
                    "flow_uid": exchange["flow_uid"],
                    "reason": "forbidden_exchange_with_link_anomaly" if link_flag else "forbidden_exchange",
                }
                proposal["proposal_id"] = canonical_digest(proposal)
                proposals.append(proposal)
            for device_id, score in gnn_devices.items():
                if score.get("behavioral_flag") is True and not any(p["target_device_id"] == device_id for p in proposals):
                    proposal = {
                        "tier": "alert", "target_device_id": device_id,
                        "binding": self.by_id.get(device_id), "scope": None,
                        "reason": "behavioral_anomaly_requires_flow_attribution",
                    }
                    proposal["proposal_id"] = canonical_digest(proposal)
                    proposals.append(proposal)
        enforcement_eligible = (
            joined["observation_kind"] == "live" and not joined["partial"] and _gnn_healthy(gnn)
            and self.deployment["decision"]["mode"] == "enforce"
        )
        decision = {
            "schema_version": "automud.decision.v1",
            "join_id": joined["join_id"],
            **{field: joined[field] for field in ("run_id", "session_id", "sensor_id", "inventory_version", "window_start", "window_end", "observation_kind")},
            "mode": self.deployment["decision"]["mode"],
            "enforcement_eligible": enforcement_eligible,
            "proposals": proposals,
            "withheld_reasons": reasons + (["engineering_observation"] if joined["observation_kind"] == "engineering" else []),
            "decided_at": self.now(),
        }
        decision["decision_id"] = canonical_digest({k: v for k, v in decision.items() if k != "decided_at"})
        return decision


def _gnn_healthy(gnn):
    if not gnn:
        return False
    health = gnn.get("health", {})
    return bool(health.get("complete") and health.get("sensor_healthy") and health.get("clock_synchronized") and health.get("capture_drops") == 0)

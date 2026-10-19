import time

from integration.live.common import canonical_digest, read_json
from integration.live.config import bindings


def _permission_key(initiator, responder, row):
    return initiator, responder, row.get("proto"), row.get("resp_p")


class MUDEngine:
    """Evaluate observed tuples against a versioned, explicit MUD permission set."""

    def __init__(self, deployment, now=time.time):
        self.deployment = deployment
        self.now = now
        self.policy = read_json(deployment["_policy_path"])
        if self.policy.get("schema_version") != "automud.mud-policy.v1":
            raise ValueError("Unsupported MUD policy")
        self.by_ip, self.by_id = bindings(deployment)
        known = set(self.policy.get("device_policies", {}))
        missing = set(self.by_id) - known
        if missing:
            raise ValueError("Missing MUD policy mapping: " + ", ".join(sorted(missing)))
        self.permissions = {}
        for rule in self.policy.get("permissions", []):
            key = (rule["initiator"], rule["responder"], rule["proto"], rule["service_port"])
            if key in self.permissions:
                raise ValueError(f"Duplicate MUD permission: {key}")
            self.permissions[key] = rule

    def evaluate(self, window):
        exchanges = []
        for row in window["telemetry"]:
            if not row.get("new_flow", False):
                continue
            initiator = self.by_ip.get(row["orig_h"])
            responder = self.by_ip.get(row["resp_h"])
            base = {
                "flow_uid": row["uid"],
                "observed_at": row["flow_start"],
                "initiator_ip": row["orig_h"],
                "responder_ip": row["resp_h"],
                "proto": row["proto"],
                "service_port": row.get("resp_p"),
                "initiator_device_id": initiator["device_id"] if initiator else None,
                "responder_device_id": responder["device_id"] if responder else None,
            }
            if initiator is None:
                result, reason, rule = "unknown_device", "initiator_not_in_inventory", None
            elif responder is None:
                result, reason, rule = "unknown_policy", "external_name_or_network_context_unavailable", None
            else:
                key = _permission_key(initiator["device_id"], responder["device_id"], row)
                rule = self.permissions.get(key)
                result = "allowed" if rule else "denied"
                reason = rule["reason"] if rule else "no_matching_permission"
            exchanges.append({**base, "permission": result, "reason": reason, "matched_rule": rule})
        evidence = {
            "schema_version": "automud.mud-evidence.v1",
            "run_id": window["run_id"],
            "session_id": window["session_id"],
            "sensor_id": window["sensor_id"],
            "inventory_version": window["inventory_version"],
            "window_start": window["window_start"],
            "window_end": window["window_end"],
            "observation_kind": window["observation_kind"],
            "policy_version": self.policy["policy_version"],
            "health": {"available": True, "reason": None, "evaluated_at": self.now()},
            "exchanges": exchanges,
        }
        evidence["evidence_id"] = _evidence_id(evidence)
        return evidence


def unavailable_mud(window, policy_version, reason, now=time.time):
    evidence = {
        "schema_version": "automud.mud-evidence.v1",
        "run_id": window["run_id"], "session_id": window["session_id"],
        "sensor_id": window["sensor_id"], "inventory_version": window["inventory_version"],
        "window_start": window["window_start"], "window_end": window["window_end"],
        "observation_kind": window["observation_kind"], "policy_version": policy_version,
        "health": {"available": False, "reason": str(reason), "evaluated_at": now()},
        "exchanges": [],
    }
    evidence["evidence_id"] = _evidence_id(evidence)
    return evidence


def _evidence_id(evidence):
    identity = dict(evidence)
    identity["health"] = {key: value for key, value in evidence["health"].items() if key != "evaluated_at"}
    return canonical_digest(identity)

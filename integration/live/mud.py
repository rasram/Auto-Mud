import time
import ipaddress

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
        self.by_id = {device["device_id"]: device for device in deployment["devices"]}
        self.policy_hash = canonical_digest(self.policy)
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
        self.external_permissions = []
        for rule in self.policy.get("external_permissions", []):
            if rule.get("initiator") not in self.by_id:
                raise ValueError("Unknown external-permission initiator")
            if rule.get("proto") not in ("tcp", "udp") or not 1 <= int(rule.get("service_port", 0)) <= 65535:
                raise ValueError("Invalid external MUD service")
            if bool(rule.get("network")) == bool(rule.get("fqdn")):
                raise ValueError("External permission requires exactly one network or fqdn")
            normalized = dict(rule)
            if normalized.get("network"):
                normalized["network"] = str(ipaddress.ip_network(normalized["network"], strict=False))
            self.external_permissions.append(normalized)

    def evaluate(self, window, name_evidence=None):
        by_ip, _ = bindings(self.deployment, at=window["window_start"])
        name_evidence = name_evidence or []
        exchanges = []
        for row in window["telemetry"]:
            if not row.get("new_flow", False):
                continue
            initiator = by_ip.get(row["orig_h"])
            responder = by_ip.get(row["resp_h"])
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
                rule = self._external_rule(initiator["device_id"], row, window, name_evidence)
                if rule:
                    result, reason = "allowed", rule["reason"]
                else:
                    result, reason = "unknown_policy", "no_verified_external_name_or_network_permission"
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
            "policy_hash": self.policy_hash,
            "health": {"available": True, "reason": None, "evaluated_at": self.now()},
            "exchanges": exchanges,
        }
        evidence["evidence_id"] = _evidence_id(evidence)
        return evidence

    def _external_rule(self, initiator_id, row, window, name_evidence):
        address = ipaddress.ip_address(row["resp_h"])
        for rule in self.external_permissions:
            if (
                rule["initiator"] != initiator_id or rule["proto"] != row["proto"]
                or int(rule["service_port"]) != int(row.get("resp_p", -1))
            ):
                continue
            if rule.get("network") and address in ipaddress.ip_network(rule["network"]):
                return rule
            if not rule.get("fqdn"):
                continue
            for evidence in name_evidence:
                if evidence.get("sensor_id") != window["sensor_id"]:
                    continue
                if evidence.get("name", "").rstrip(".").lower() != rule["fqdn"].rstrip(".").lower():
                    continue
                if not (
                    float(evidence["valid_from"]) <= float(row["flow_start"])
                    < float(evidence["valid_until"])
                ):
                    continue
                if row["resp_h"] in evidence.get("addresses", []):
                    return rule
        return None


def unavailable_mud(window, policy_version, reason, now=time.time, policy_hash=None):
    evidence = {
        "schema_version": "automud.mud-evidence.v1",
        "run_id": window["run_id"], "session_id": window["session_id"],
        "sensor_id": window["sensor_id"], "inventory_version": window["inventory_version"],
        "window_start": window["window_start"], "window_end": window["window_end"],
        "observation_kind": window["observation_kind"], "policy_version": policy_version,
        "policy_hash": policy_hash,
        "health": {"available": False, "reason": str(reason), "evaluated_at": now()},
        "exchanges": [],
    }
    evidence["evidence_id"] = _evidence_id(evidence)
    return evidence


def _evidence_id(evidence):
    identity = dict(evidence)
    identity["health"] = {key: value for key, value in evidence["health"].items() if key != "evaluated_at"}
    return canonical_digest(identity)

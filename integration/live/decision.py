import json
import sqlite3
import time
from pathlib import Path

from integration.live.common import canonical_digest, read_json, resolve_project_path
from integration.live.config import bindings


class DecisionState:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS decision_scopes (
                    scope_key TEXT PRIMARY KEY,
                    last_window INTEGER NOT NULL,
                    consecutive INTEGER NOT NULL,
                    last_proposed_at REAL NOT NULL
                )
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def observe(self, scope_key, window_start, observed_at):
        with self._connect() as db:
            row = db.execute(
                "SELECT last_window,consecutive,last_proposed_at FROM decision_scopes WHERE scope_key=?",
                (scope_key,),
            ).fetchone()
            if row and row[0] == window_start:
                return {"consecutive": row[1], "previous_proposed_at": None, "replay": True}
            consecutive = row[1] + 1 if row and row[0] == window_start - 60 else 1
            previous_at = row[2] if row else None
            db.execute(
                "INSERT INTO decision_scopes VALUES (?,?,?,?) "
                "ON CONFLICT(scope_key) DO UPDATE SET last_window=excluded.last_window,"
                "consecutive=excluded.consecutive,last_proposed_at=excluded.last_proposed_at",
                (scope_key, int(window_start), consecutive, float(observed_at)),
            )
        return {"consecutive": consecutive, "previous_proposed_at": previous_at, "replay": False}


class DecisionEngine:
    def __init__(self, deployment, now=time.time):
        self.deployment = deployment
        self.now = now
        decision = deployment["decision"]
        policy_path = decision.get("policy")
        self.policy = read_json(resolve_project_path(policy_path)) if policy_path else {
            "schema_version": "automud.decision-policy.v1",
            "policy_version": "built-in-observe-v1",
            "cooldown_seconds": decision.get("cooldown_seconds", 120),
            "escalation": {"enabled": False, "consecutive_denied": 3},
        }
        if self.policy.get("schema_version") != "automud.decision-policy.v1":
            raise ValueError("Unsupported decision policy")
        state_path = deployment["paths"].get(
            "state_db", str(Path(deployment["paths"]["queue"]) / "live-state.sqlite3"),
        )
        self.state = DecisionState(state_path)
        self.override_path = decision.get("override_file")

    def decide(self, joined):
        _, by_id = bindings(self.deployment, at=joined["window_start"])
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
                device = by_id.get(device_id)
                proposal = {
                    "tier": tier,
                    "target_device_id": device_id,
                    "binding": {
                        "mac": device["mac"], "ip": device["ip"],
                        "switch_port": int(device["switch_port"]),
                    } if device else None,
                    "scope": {
                        "proto": exchange["proto"],
                        "destination_ip": exchange["responder_ip"],
                        "destination_port": exchange["service_port"],
                    },
                    "mud_evidence_id": mud["evidence_id"],
                    "flow_uid": exchange["flow_uid"],
                    "reason": "forbidden_exchange_with_link_anomaly" if link_flag else "forbidden_exchange",
                }
                self._apply_state(proposal, joined)
                proposals.append(proposal)
            for device_id, score in gnn_devices.items():
                if score.get("behavioral_flag") is True and not any(p["target_device_id"] == device_id for p in proposals):
                    proposal = {
                        "tier": "alert", "target_device_id": device_id,
                        "binding": by_id.get(device_id), "scope": None,
                        "reason": "behavioral_anomaly_requires_flow_attribution",
                    }
                    self._apply_state(proposal, joined)
                    proposals.append(proposal)
        base_eligible = (
            joined["observation_kind"] == "live" and not joined["partial"] and _gnn_healthy(gnn)
            and self.deployment["decision"]["mode"] == "enforce"
        )
        dispatchable = any(
            proposal.get("dispatch_eligible") and proposal["tier"] in ("block", "rate_limit")
            for proposal in proposals
        )
        decision = {
            "schema_version": "automud.decision.v1",
            "join_id": joined["join_id"],
            **{field: joined[field] for field in (
                "run_id", "session_id", "sensor_id", "inventory_version",
                "window_start", "window_end", "observation_kind",
            )},
            "mode": self.deployment["decision"]["mode"],
            "decision_policy_version": self.policy["policy_version"],
            "enforcement_eligible": bool(base_eligible and dispatchable),
            "proposals": proposals,
            "withheld_reasons": reasons + (
                ["engineering_observation"] if joined["observation_kind"] == "engineering" else []
            ),
            "decided_at": self.now(),
        }
        if base_eligible and proposals and not dispatchable:
            decision["withheld_reasons"].append("proposal_cooldown_or_override")
        decision["decision_id"] = canonical_digest({key: value for key, value in decision.items() if key != "decided_at"})
        return decision

    def _apply_state(self, proposal, joined):
        current = float(self.now())
        scope_key = canonical_digest({
            "target_device_id": proposal["target_device_id"],
            "scope": proposal.get("scope"), "tier": proposal["tier"],
        })
        observed = self.state.observe(scope_key, joined["window_start"], current)
        cooldown = int(self.policy.get("cooldown_seconds", 120))
        cooldown_active = bool(
            observed["previous_proposed_at"] is not None
            and current - observed["previous_proposed_at"] < cooldown
        )
        escalation = self.policy.get("escalation", {})
        if (
            escalation.get("enabled") and proposal["tier"] == "alert"
            and proposal["reason"] == "forbidden_exchange"
            and observed["consecutive"] >= int(escalation.get("consecutive_denied", 3))
        ):
            proposal["tier"] = "block"
            proposal["reason"] = "repeated_forbidden_exchange"
        proposal_id = canonical_digest(proposal)
        override = self._active_override(proposal, current)
        proposal["policy_state"] = {
            "scope_key": scope_key, "consecutive_windows": observed["consecutive"],
            "cooldown_seconds": cooldown, "cooldown_active": cooldown_active,
            "override": override,
        }
        proposal["dispatch_eligible"] = bool(
            proposal.get("binding") and not cooldown_active and override is None
        )
        proposal["proposal_id"] = proposal_id

    def _active_override(self, proposal, current):
        if not self.override_path:
            return None
        path = resolve_project_path(self.override_path)
        if not Path(path).exists():
            return None
        value = read_json(path)
        if value.get("schema_version") != "automud.human-overrides.v1":
            raise ValueError("Unsupported human override file")
        for override in value.get("overrides", []):
            if override.get("action") != "suppress":
                raise ValueError("Only suppressing human overrides are supported")
            if not override.get("actor") or not override.get("reason") or not override.get("expires_at"):
                raise ValueError("Human override requires actor, reason and expiry")
            if float(override["expires_at"]) <= current:
                continue
            target = override.get("target_device_id")
            if target is None or target == proposal["target_device_id"]:
                return {
                    "override_id": override["override_id"], "action": "suppress",
                    "actor": override["actor"], "reason": override["reason"],
                    "expires_at": float(override["expires_at"]),
                }
        return None


def _gnn_healthy(gnn):
    if not gnn:
        return False
    health = gnn.get("health", {})
    fresh = gnn.get("integration_health", {}).get("fresh", True)
    return bool(
        fresh and health.get("complete") and health.get("sensor_healthy")
        and health.get("clock_synchronized") and health.get("capture_drops") == 0
    )

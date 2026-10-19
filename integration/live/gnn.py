import json
import os
import time

from jsonschema import Draft202012Validator

from integration.live.common import PROJECT_ROOT
from ml.live.client import Client


IDENTITY_FIELDS = (
    "observation_kind", "run_id", "session_id", "sensor_id",
    "inventory_version", "window_start", "window_end",
)
EVIDENCE_SCHEMA = json.loads(
    (PROJECT_ROOT / "configs/gnn/live/evidence.schema.json").read_text(encoding="utf-8")
)
EVIDENCE_VALIDATOR = Draft202012Validator(EVIDENCE_SCHEMA)


def validate_gnn_evidence(window, evidence, now=None, stale_after_seconds=180):
    errors = sorted(EVIDENCE_VALIDATOR.iter_errors(evidence), key=lambda error: str(error.path))
    if errors:
        raise ValueError("GNN evidence schema: " + errors[0].message)
    mismatches = [field for field in IDENTITY_FIELDS if evidence.get(field) != window.get(field)]
    if mismatches:
        raise ValueError("GNN evidence identity mismatch: " + ", ".join(mismatches))
    model = evidence["model"]
    if model["a_checkpoint"] != model["b_checkpoint"]:
        raise ValueError("E1+Q evidence does not identify one joint checkpoint")
    if evidence["head_c_trained"] is not False or evidence["enforcement_action"] is not None:
        raise ValueError("GNN evidence contains an unsupported enforcement or Head C claim")
    inventory_ids = {device["device_id"] for device in window["inventory"]}
    evidence_ids = [device["device_id"] for device in evidence["devices"]]
    if len(evidence_ids) != len(set(evidence_ids)) or set(evidence_ids) != inventory_ids:
        raise ValueError("GNN evidence device identities do not match the observation inventory")
    for device in evidence["devices"]:
        if device.get("compromised_probability") is not None:
            raise ValueError("GNN evidence must not report a compromise probability")
        for score_name, flag_name in (
            ("behavioral_score", "behavioral_flag"), ("link_anomaly", "link_flag")
        ):
            score, flag = device.get(score_name), device.get(flag_name)
            if score is None and flag is not None:
                raise ValueError(f"{flag_name} cannot be set without {score_name}")
    current = time.time() if now is None else float(now)
    age_seconds = max(0.0, current - float(window["window_end"]))
    evidence = dict(evidence)
    evidence["integration_health"] = {
        "validated_at": current,
        "age_seconds": age_seconds,
        "stale_after_seconds": int(stale_after_seconds),
        "fresh": age_seconds <= float(stale_after_seconds),
    }
    return evidence


class GNNEvidenceClient:
    """Validate service identity and evidence without importing model code."""

    def __init__(self, deployment, now=time.time, client=None):
        self.deployment = deployment
        self.now = now
        config = deployment["gnn"]
        self.client = client or Client(
            url=config["url"], token=os.environ.get("AUTOMUD_GNN_API_TOKEN"),
            timeout=config.get("timeout_seconds", 30), retries=2,
        )
        self.stale_after = int(config.get("stale_after_seconds", 180))
        self.model = None

    def probe(self):
        ready = self.client.call("/readyz")
        model = self.client.call("/v1/model")
        if not isinstance(model, dict) or not model.get("bundle_id"):
            raise ValueError("GNN service returned no active bundle identity")
        self.model = model
        return {"ready": ready, "model": model, "health": self.client.health()}

    def submit(self, window):
        evidence = validate_gnn_evidence(
            window, self.client.submit(window), now=self.now(),
            stale_after_seconds=self.stale_after,
        )
        if self.model and evidence["model"]["bundle_id"] != self.model["bundle_id"]:
            raise ValueError("GNN active bundle changed without a recorded integration probe")
        return evidence

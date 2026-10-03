"""Export JSON Schema alongside the ordered tensor-column contract."""
from ml.schema import VERSION, FEATURES, TYPES, contract, write_json
from pathlib import Path


def obj(properties, required=None):
    return {"type": "object", "properties": properties, "required": required or list(properties), "additionalProperties": True}


def export_schemas(directory):
    number = {"type": "number"}
    positive = {"type": "number", "minimum": 0}
    integer = {"type": "integer", "minimum": 0}
    string = {"type": "string", "minLength": 1}
    boolean = {"type": "boolean"}
    minute = {"type": "integer", "multipleOf": 60}
    fixed = {"const": VERSION}
    lease = obj({"ip": string, "start": number, "end": number})
    device = obj({"device_id": string, "device_type": {"enum": list(TYPES)}, "mac": string,
                  "addresses": {"type": "array", "items": lease}}, ["device_id", "device_type", "addresses"])
    manifest = obj({"schema_version": fixed, "run_id": string, "source": string, "session_id": string,
        "start": minute, "end": minute, "normal": boolean, "capture_complete": boolean,
        "replay_speed": {"type": "number", "exclusiveMinimum": 0},
        "inventory": {"type": "array", "minItems": 1, "items": device}, "capture_drops": integer},
        ["schema_version", "run_id", "source", "session_id", "start", "end", "normal", "capture_complete", "replay_speed", "inventory"])
    telemetry = obj({"schema_version": fixed, "window_start": minute, "uid": string,
        "orig_h": string, "resp_h": string, "orig_p": integer, "resp_p": integer, "proto": string,
        "flow_start": number, "orig_ip_bytes": integer, "resp_ip_bytes": integer, "orig_pkts": integer,
        "resp_pkts": integer, "observed_duration": positive, "established": boolean, "failed": boolean, "new_flow": boolean})
    label = obj({"device_id": string, "start": number, "end": number, "label": {"enum": [0, 1]},
        "role": {"enum": ["actor", "normal"]}, "evidence": string, "attack_family": string,
        "onset": {"enum": ["from_start", "later"]}}, ["device_id", "start", "end", "label", "role", "evidence"])
    label["allOf"] = [{"if": {"properties": {"label": {"const": 1}}},
                         "then": {"properties": {"role": {"const": "actor"}}, "required": ["attack_family", "onset"]}}]
    vector = {"type": "array", "minItems": len(FEATURES), "maxItems": len(FEATURES), "items": number}
    mask = {"type": "array", "minItems": len(FEATURES), "maxItems": len(FEATURES), "items": boolean}
    node = obj({"device_id": string, "device_type": {"enum": list(TYPES)}, "features": vector,
                "feature_mask": mask, "active": boolean, "available": boolean, "label": {"enum": [-1, 0, 1]}})
    edge = obj({"source": integer, "target": integer, "ip_bytes": integer, "packets": integer,
                "flow_count": integer, "new_edge": boolean, "confirmed": boolean, "protocols": {"type": "object"},
                "ports": {"type": "array", "items": string}})
    graph = obj({"schema_version": fixed, "schema_hash": string, "run_id": string, "session_id": string,
                 "source": string, "normal": boolean, "window_start": minute, "window_seconds": {"const": 60},
                 "nodes": {"type": "array", "items": node, "minItems": 1}, "edges": {"type": "array", "items": edge}})
    for name, schema in {"manifest": manifest, "telemetry": telemetry, "label": label, "graph": graph}.items():
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["title"] = f"AutoMUD {name} v1"
        write_json(Path(directory) / f"{name}.schema.json", schema)
    write_json(Path(directory) / "features.json", contract())

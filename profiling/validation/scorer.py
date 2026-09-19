"""Score generated MUD profiles against held-out MUDgee references."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REFERENCE_SUFFIXES = ("mud", "profile")
NAME_ALIASES = {
    "augustdoorbell": "augustdoorbellcam",
    "belkinwemomotionsensor": "wemomotion",
    "belkinwemoswitch": "wemoswitch",
    "blipcarebpmeter": "blipcarebpmeter",
    "hellobarbie": "hellobarbie",
    "ihome": "ihomepowerplug",
    "nestdropcam": "dropcam",
    "nestprotect": "nestsmokesensor",
    "nestprotectsmokealarm": "nestsmokesensor",
    "netatmowelcome": "netatmocamera",
    "philipshue": "huebulb",
    "pixstarphotoframe": "pixstarphotoframe",
    "ringdoorbell": "ringdoorbell",
    "samsungcamera": "samsungsmartcam",
    "samsungsmartthings": "smartthings",
    "tplinkcamera": "tplinkcamera",
    "tplinksmartplug": "tplinkplug",
    "withingsbabymonitor": "withingsbabymonitor",
    "withingssleepsensor": "withingssleepsensor",
    "withingssmartscale": "withingscardio",
}


def canonical_name(value: str) -> str:
    name = re.sub(r"[^a-z0-9]+", "", value.lower())
    name = re.sub(r"[0-9a-f]{12}$", "", name)
    for suffix in REFERENCE_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return NAME_ALIASES.get(name, name)


@dataclass(frozen=True, order=True)
class AceFeature:
    direction: str
    family: str
    protocol: str
    endpoint: str
    port: str


def _policy_acl_names(document: dict[str, Any]) -> dict[str, str]:
    mud = document.get("ietf-mud:mud", {})
    result: dict[str, str] = {}
    for policy, direction in (("from-device-policy", "from-device"), ("to-device-policy", "to-device")):
        lists = mud.get(policy, {}).get("access-lists", {}).get("access-list", [])
        for item in lists or []:
            if isinstance(item, dict) and item.get("name"):
                result[str(item["name"])] = direction
    return result


def _normalise_network(value: Any) -> str:
    try:
        return str(ipaddress.ip_network(str(value), strict=False))
    except ValueError:
        return str(value).lower()


def _endpoint(matches: dict[str, Any], family: str) -> str:
    network = matches.get(family, {}) if family in {"ipv4", "ipv6"} else {}
    for key, value in network.items():
        if key.endswith("dnsname"):
            return "dns:" + str(value).lower().rstrip(".")
    mud = matches.get("ietf-mud:mud", {})
    if mud.get("controller"):
        return "controller:" + str(mud["controller"]).lower()
    for key, value in network.items():
        if key.endswith("network"):
            return "network:" + _normalise_network(value)
    if "local-networks" in mud:
        return "local-networks"
    if mud.get("same-manufacturer") is not None:
        return "same-manufacturer"
    if mud.get("manufacturer"):
        return "manufacturer:" + str(mud["manufacturer"]).lower()
    return "any"


def _protocol(matches: dict[str, Any], family: str) -> str:
    if family == "ethernet":
        eth = matches.get("eth", {})
        return "eth:" + str(eth.get("ethertype", "any")).lower()
    value = matches.get(family, {}).get("protocol", "any")
    return str(value).lower()


def _transport_port(matches: dict[str, Any], protocol: str, direction: str) -> str:
    layer_name = {"6": "tcp", "17": "udp"}.get(protocol)
    if not layer_name:
        return "any"
    layer = matches.get(layer_name, {})
    preferred = "destination-port" if direction == "from-device" else "source-port"
    port = layer.get(preferred) or layer.get("source-port") or layer.get("destination-port")
    if not isinstance(port, dict):
        return "any"
    if "port" in port:
        return str(port["port"])
    lower = port.get("lower-port")
    upper = port.get("upper-port")
    return f"{lower}-{upper}" if lower is not None or upper is not None else "any"


def extract_features(document: dict[str, Any]) -> set[AceFeature]:
    directions = _policy_acl_names(document)
    features: set[AceFeature] = set()
    acls = document.get("ietf-access-control-list:access-lists", {}).get("acl", []) or []
    for acl in acls:
        acl_name = str(acl.get("name", ""))
        direction = directions.get(acl_name)
        if not direction:
            direction = "from-device" if acl_name.startswith("from-") else "to-device"
        acl_type = str(acl.get("type", ""))
        family = "ethernet" if "ethernet" in acl_type else "ipv6" if "ipv6" in acl_type else "ipv4"
        for ace in acl.get("aces", {}).get("ace", []) or []:
            matches = ace.get("matches", {}) or {}
            protocol = _protocol(matches, family)
            features.add(
                AceFeature(
                    direction=direction,
                    family=family,
                    protocol=protocol,
                    endpoint=_endpoint(matches, family),
                    port=_transport_port(matches, protocol, direction),
                )
            )
    return features


def _prf(reference: set[Any], generated: set[Any]) -> dict[str, float | int]:
    overlap = reference & generated
    precision = len(overlap) / len(generated) if generated else 0.0
    recall = len(overlap) / len(reference) if reference else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "matched": len(overlap),
        "reference": len(reference),
        "generated": len(generated),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _endpoint_equivalent(reference: tuple[str, str], generated: tuple[str, str]) -> bool:
    if reference[0] != generated[0]:
        return False
    reference_value = reference[1]
    generated_value = generated[1]
    if reference_value == generated_value:
        return True
    if not (reference_value.startswith("network:") and generated_value.startswith("network:")):
        return False
    try:
        reference_network = ipaddress.ip_network(reference_value.removeprefix("network:"), strict=False)
        generated_network = ipaddress.ip_network(generated_value.removeprefix("network:"), strict=False)
    except ValueError:
        return False
    return reference_network.version == generated_network.version and reference_network.overlaps(generated_network)


def _endpoint_prf(
    reference: set[tuple[str, str]], generated: set[tuple[str, str]]
) -> tuple[dict[str, float | int], set[tuple[str, str]], set[tuple[str, str]]]:
    unmatched_generated = set(generated)
    missing_reference: set[tuple[str, str]] = set()
    matched = 0
    for reference_endpoint in sorted(reference):
        candidate = next(
            (
                generated_endpoint
                for generated_endpoint in sorted(unmatched_generated)
                if _endpoint_equivalent(reference_endpoint, generated_endpoint)
            ),
            None,
        )
        if candidate is None:
            missing_reference.add(reference_endpoint)
        else:
            matched += 1
            unmatched_generated.remove(candidate)
    precision = matched / len(generated) if generated else 0.0
    recall = matched / len(reference) if reference else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics: dict[str, float | int] = {
        "matched": matched,
        "reference": len(reference),
        "generated": len(generated),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
    return metrics, missing_reference, unmatched_generated


def compare_profiles(generated: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    generated_features = extract_features(generated)
    reference_features = extract_features(reference)
    generated_endpoints = {(item.direction, item.endpoint) for item in generated_features if item.endpoint != "any"}
    reference_endpoints = {(item.direction, item.endpoint) for item in reference_features if item.endpoint != "any"}
    generated_services = {(item.direction, item.family, item.protocol, item.port) for item in generated_features}
    reference_services = {(item.direction, item.family, item.protocol, item.port) for item in reference_features}
    generated_protocols = {(item.direction, item.family, item.protocol) for item in generated_features}
    reference_protocols = {(item.direction, item.family, item.protocol) for item in reference_features}
    endpoints, missing_endpoints, extra_endpoints = _endpoint_prf(reference_endpoints, generated_endpoints)
    services = _prf(reference_services, generated_services)
    protocols = _prf(reference_protocols, generated_protocols)
    aces = _prf(reference_features, generated_features)
    overall = 100 * (
        0.45 * float(endpoints["f1"])
        + 0.25 * float(services["f1"])
        + 0.15 * float(protocols["f1"])
        + 0.15 * float(aces["f1"])
    )
    return {
        "profile_fidelity_percent": round(100 * float(endpoints["recall"]), 2),
        "overall_similarity_percent": round(overall, 2),
        "endpoints": endpoints,
        "services": services,
        "protocols": protocols,
        "aces": aces,
        "missing_reference_endpoints": sorted(f"{direction}|{endpoint}" for direction, endpoint in missing_endpoints),
        "extra_generated_endpoints": sorted(f"{direction}|{endpoint}" for direction, endpoint in extra_endpoints),
    }


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _document_name(path: Path, document: dict[str, Any]) -> str:
    mud_name = document.get("ietf-mud:mud", {}).get("systeminfo")
    return canonical_name(str(mud_name or path.stem))


def score_directories(generated_dir: str | Path, reference_dir: str | Path) -> dict[str, Any]:
    reference_index: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(Path(reference_dir).glob("*.json")):
        document = _load_json(path)
        reference_index[_document_name(path, document)] = (path, document)

    results = []
    unmatched = []
    for generated_path in sorted(Path(generated_dir).glob("*.json")):
        generated = _load_json(generated_path)
        name = _document_name(generated_path, generated)
        match = reference_index.get(name)
        if not match:
            unmatched.append({"generated": generated_path.name, "canonical_name": name})
            continue
        reference_path, reference = match
        results.append(
            {
                "device": name,
                "generated_file": generated_path.name,
                "reference_file": reference_path.name,
                **compare_profiles(generated, reference),
            }
        )
    summary = {
        "profiles_scored": len(results),
        "mean_profile_fidelity_percent": round(sum(row["profile_fidelity_percent"] for row in results) / len(results), 2) if results else 0.0,
        "mean_overall_similarity_percent": round(sum(row["overall_similarity_percent"] for row in results) / len(results), 2) if results else 0.0,
    }
    return {"summary": summary, "profiles": results, "unmatched_generated_profiles": unmatched}


def write_report(report: dict[str, Any], output_json: str | Path, output_csv: str | Path | None = None) -> None:
    json_path = Path(output_json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if output_csv is None:
        return
    csv_path = Path(output_csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "device", "generated_file", "reference_file", "profile_fidelity_percent",
        "overall_similarity_percent", "endpoint_precision", "endpoint_recall",
        "service_f1", "protocol_f1", "ace_f1",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["profiles"]:
            writer.writerow(
                {
                    "device": row["device"],
                    "generated_file": row["generated_file"],
                    "reference_file": row["reference_file"],
                    "profile_fidelity_percent": row["profile_fidelity_percent"],
                    "overall_similarity_percent": row["overall_similarity_percent"],
                    "endpoint_precision": row["endpoints"]["precision"],
                    "endpoint_recall": row["endpoints"]["recall"],
                    "service_f1": row["services"]["f1"],
                    "protocol_f1": row["protocols"]["f1"],
                    "ace_f1": row["aces"]["f1"],
                }
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_dir", type=Path)
    parser.add_argument("reference_dir", type=Path)
    parser.add_argument("--output-json", type=Path, default=Path("profiling/validation/results/profile_scores.json"))
    parser.add_argument("--output-csv", type=Path, default=Path("profiling/validation/results/profile_scores.csv"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = score_directories(args.generated_dir, args.reference_dir)
    write_report(report, args.output_json, args.output_csv)
    print(json.dumps(report["summary"], indent=2))
    if report["unmatched_generated_profiles"]:
        print("Unmatched generated profiles:", json.dumps(report["unmatched_generated_profiles"]))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

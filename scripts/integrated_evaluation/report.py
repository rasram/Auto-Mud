"""Recount labelled detector, policy and response records without running services."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

if __package__:
    from .metrics import detection, policy_confusion
else:
    from metrics import detection, policy_confusion


def read_records(path):
    """Accept a JSON array or newline-delimited JSON objects."""
    text = Path(path).read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("["):
        records = json.loads(text)
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise ValueError("Records must be JSON objects in an array or JSONL file")
    return records


def response_confusion(records):
    counts = Counter(TP=0, FP=0, TN=0, FN=0, unavailable=0, excluded=0, population=0)
    for row in records:
        if not row.get("eligible", True):
            counts["excluded"] += 1
            continue
        required, proposed = row["required"], row["proposed"]
        if type(required) is not bool or proposed is not None and type(proposed) is not bool:
            raise ValueError("Response required must be boolean; proposed boolean or null")
        counts["population"] += 1
        if proposed is None:
            counts["unavailable"] += 1
        else:
            counts[("TP" if proposed else "FN") if required else ("FP" if proposed else "TN")] += 1
    return dict(counts)


def build_report(detection_path=None, mud_path=None, response_path=None):
    result = {
        "schema_version": "automud.labelled-record-recount.v1",
        "status": "recount_only",
        "inputs": {},
        "limitations": [
            "A recount does not validate labels, coverage of collected traffic or feature extraction.",
            "Response proposal counts do not prove installed actions or measured network effects.",
        ],
    }
    for kind, path in (("detection", detection_path), ("mud", mud_path), ("response", response_path)):
        if path is None:
            continue
        records = read_records(path)
        result["inputs"][kind] = {
            "file": Path(path).name,
            "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            "records": len(records),
        }
        if kind == "detection":
            if any(row.get("head") not in ("A", "B") for row in records):
                raise ValueError("Each detection record must identify head A or B")
            result[kind] = {
                head: detection(row for row in records if row["head"] == head)
                for head in ("A", "B")
            }
        elif kind == "mud":
            counts = Counter(policy_confusion(records))
            for key in ("TP", "FP", "TN", "FN", "eligible", "unsupported",
                        "unavailable_forbidden", "unavailable_permitted"):
                counts.setdefault(key, 0)
            scored = sum(counts[key] for key in ("TP", "FP", "TN", "FN"))
            result[kind] = {
                **counts,
                "binary_coverage_of_all_records": scored / len(records) if records else None,
                "agreement_on_scored_records": (counts["TP"] + counts["TN"]) / scored if scored else None,
            }
        else:
            result[kind] = response_confusion(records)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detection", type=Path, help="A/B label, flag and eligibility records")
    parser.add_argument("--mud", type=Path, help="Expected and actual permission records")
    parser.add_argument("--response", type=Path, help="Required and proposed response booleans")
    parser.add_argument("--output", type=Path, help="New output file; defaults to standard output")
    args = parser.parse_args()
    if not any((args.detection, args.mud, args.response)):
        parser.error("Supply at least one input record file")
    try:
        result = build_report(args.detection, args.mud, args.response)
        text = json.dumps(result, indent=2, allow_nan=False) + "\n"
        if args.output:
            # Never overwrite input evidence or a previous report.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(text)
        else:
            print(text, end="")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

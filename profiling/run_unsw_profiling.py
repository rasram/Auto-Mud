"""Generate MUD profiles for available UNSW PCAPs and score those profiles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from profiling.profile_engine.generator import generate_directory
from profiling.validation.scorer import score_directories, write_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _default_path(flat: str, automud: str) -> Path:
    flat_path = PROJECT_ROOT / flat
    return flat_path if flat_path.exists() else PROJECT_ROOT / automud


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pcap-dir",
        type=Path,
        default=_default_path("pcaps", "data/raw/unsw_iot/traffic/pcaps"),
    )
    parser.add_argument(
        "--reference-dir",
        type=Path,
        default=_default_path("mudgee-profiles", "data/raw/mudgee_profiles"),
    )
    parser.add_argument(
        "--generated-dir",
        type=Path,
        default=(PROJECT_ROOT / "results/generated_muds" if (PROJECT_ROOT / "pcaps").exists() else PROJECT_ROOT / "data/processed/generated_muds"),
    )
    parser.add_argument("--results-dir", type=Path, default=PROJECT_ROOT / "profiling/validation/results")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=PROJECT_ROOT / "temp/profile_cache",
        help="Restart-safe cache of capture-derived observations",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        help="Fixed support threshold for unnamed IPs; default is 1%% of observed packets, capped at 5000",
    )
    parser.add_argument("--min-named-packets", type=int, default=2)
    parser.add_argument("--min-window-support", type=float, default=0.0)
    parser.add_argument("--require-bidirectional-public-ip", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    outputs = generate_directory(
        args.pcap_dir,
        args.generated_dir,
        min_packets=args.min_packets,
        min_named_packets=args.min_named_packets,
        min_window_support=args.min_window_support,
        require_bidirectional_public_ip=args.require_bidirectional_public_ip,
        cache_directory=args.cache_dir,
    )
    report = score_directories(args.generated_dir, args.reference_dir)
    write_report(
        report,
        args.results_dir / "profile_scores.json",
        args.results_dir / "profile_scores.csv",
    )
    print(f"Generated {len(outputs)} profiles in {args.generated_dir}")
    print(json.dumps(report["summary"], indent=2))
    return 2 if report["unmatched_generated_profiles"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

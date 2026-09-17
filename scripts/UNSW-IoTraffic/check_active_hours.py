"""
check_active_hours.py

Plots the hour-of-day activity histogram for one (or several) single-day
flow CSV files, so you can check whether a device's "always-on" pattern
in the aggregated calibration is real, or an artifact of pooling many
days together. Also flags days that are likely unreliable for
calibration (too few flows, or activity concentrated in a single hour --
usually a sign of a truncated/partial capture).

Usage:
    # Single day
    python check_active_hours.py --files day1.csv --out day1_hours.png

    # Overlay several days for the same device to compare shapes
    python check_active_hours.py --files day1.csv day2.csv day3.csv --out compare_hours.png

    # Process every CSV file in a folder
    python check_active_hours.py --folder ./data --out compare_hours.png

    # Combine explicit files with all CSVs from a folder
    python check_active_hours.py --files extra_day.csv --folder ./data
"""

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # no display needed, just save to file
import matplotlib.pyplot as plt
import pandas as pd

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"


def hourly_histogram(csv_path: Path):
    df = pd.read_csv(csv_path, usecols=["time"], low_memory=False)
    total_flows = len(df)
    # 'time' is documented as seconds since epoch, UTC
    ts = pd.to_datetime(df["time"], unit="s", utc=True, errors="coerce")
    hours = ts.dt.hour.dropna()

    hist = hours.value_counts(normalize=True).reindex(range(24), fill_value=0.0)
    hist.index.name = "hour"
    return hist, total_flows


def main():
    parser = argparse.ArgumentParser(description="Check hour-of-day activity pattern for one or more single-day flow CSVs.")
    parser.add_argument("--files", nargs="+", help="One or more single-day CSV files (same device).")
    parser.add_argument("--folder", type=Path, help="Folder containing single-day CSV files.")
    parser.add_argument("--out", default=str(RESULTS_DIR / "active_hours_check.png"), help="Output plot path.")
    parser.add_argument("--min-flows", type=int, default=50,
                         help="Absolute floor: flag days with fewer than this many total flows.")
    parser.add_argument("--min-relative-fraction", type=float, default=0.2,
                         help="Additionally flag days below this fraction of the median flow count "
                              "across all files passed in (adapts the threshold per device).")
    parser.add_argument("--max-single-hour-share", type=float, default=0.5,
                         help="Flag days where one hour accounts for more than this fraction of all flows "
                              "as likely truncated/partial captures.")
    args = parser.parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    files = list(args.files or [])
    if args.folder:
        files.extend(str(path) for path in sorted(args.folder.glob("*.csv")))
    if not files:
        parser.error("provide --files, --folder, or both")

    # First pass: read flow counts for all files so we can compute this
    # device's own typical daily volume before flagging anything.
    results = {}
    for f in files:
        path = Path(f)
        hist, total_flows = hourly_histogram(path)
        results[f] = (path, hist, total_flows)

    median_flows = float(pd.Series([r[2] for r in results.values()]).median()) if results else 0.0
    relative_floor = args.min_relative_fraction * median_flows
    print(f"Median daily flow count across {len(results)} file(s): {median_flows:.0f} "
          f"(relative floor = {relative_floor:.0f})\n")

    fig, ax = plt.subplots(figsize=(10, 5))
    flagged_days = []

    for f, (path, hist, total_flows) in results.items():
        ax.plot(hist.index, hist.values, marker="o", label=path.stem)

        flat_baseline = 1 / 24
        max_deviation = (hist - flat_baseline).abs().max()
        peak_share = hist.max()

        issues = []
        if total_flows < args.min_flows:
            issues.append(f"low flow count ({total_flows})")
        elif total_flows < relative_floor:
            issues.append(f"low relative to this device's median ({total_flows} vs median {median_flows:.0f})")
        if peak_share > args.max_single_hour_share:
            issues.append(f"activity concentrated in one hour ({peak_share:.0%} of flows)")

        status = "; ".join(issues) if issues else (
            "looks flat / near-uniform" if max_deviation < 0.02 else "shows a real peak/trough"
        )
        print(f"{path.name}: {total_flows} flows -> {status}")

        if issues:
            flagged_days.append(path.name)

    ax.axhline(1 / 24, color="gray", linestyle="--", linewidth=1, label="perfectly uniform (1/24)")
    ax.set_xlabel("Hour of day (UTC)")
    ax.set_ylabel("Fraction of flows")
    ax.set_title("Hourly activity pattern — single day(s)")
    ax.set_xticks(range(24))
    ax.legend(fontsize=7, ncol=2)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print(f"\nSaved plot to {args.out}")

    if flagged_days:
        print(f"\n{len(flagged_days)} day(s) flagged as likely unreliable for calibration:")
        for d in flagged_days:
            print(f"  - {d}")
        print("Consider excluding these from the aggregate calibration (calibrate_device_profiles.py "
              "already does this automatically via the same min-flows / relative-fraction / "
              "single-hour-share logic).")


if __name__ == "__main__":
    main()
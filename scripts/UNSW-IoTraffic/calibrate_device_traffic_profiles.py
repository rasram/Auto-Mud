"""
calibrate_device_traffic_profiles.py

Walks a folder of per-device flow CSVs (UNSW-style columns), groups files by
device (inferred from filename), and computes the distribution statistics
needed to parameterize the Mininet traffic-generation scripts:

    - byte / packet volume distributions
    - payload size distributions
    - flow duration distributions
    - inter-arrival time (burstiness) distributions
    - distinct-destination counts and destination reuse
    - port / protocol distributions
    - active-hours histogram

Usage:
    python calibrate_device_traffic_profiles.py --folder /path/to/csvs

Assumes columns matching:
    time, srcMac, dstMac, ethType, srcIp, dstIp, ipProto, srcPort, dstPort,
    flowSeqNum, srcNumPackets, dstNumPackets, srcPayloadSize, dstPayloadSize,
    srcAvgPayloadSize, dstAvgPayloadSize, srcMaxPayloadSize, dstMaxPayloadSize,
    srcStdDevPayloadSize, dstStdDevPayloadSize, flowDuration,
    srcAvgInterarrivalTime, dstAvgInterarrivalTime, avgInterarrivalTime,
    srcStdDevInterarrivalTime, dstStdDevInterarrivalTime,
    allMatchedProtocols, protocol
"""

import argparse
import json
import re
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "artifacts"
    / "traffic_generation"
    / "device_traffic_profiles.json"
)

# ---------------------------------------------------------------------------
# Columns of interest
# ---------------------------------------------------------------------------

NUMERIC_COLS = [
    "srcNumPackets", "dstNumPackets",
    "srcPayloadSize", "dstPayloadSize",
    "srcAvgPayloadSize", "dstAvgPayloadSize",
    "srcMaxPayloadSize", "dstMaxPayloadSize",
    "srcStdDevPayloadSize", "dstStdDevPayloadSize",
    "flowDuration",
    "srcAvgInterarrivalTime", "dstAvgInterarrivalTime", "avgInterarrivalTime",
    "srcStdDevInterarrivalTime", "dstStdDevInterarrivalTime",
]

CATEGORICAL_COLS = ["ipProto", "protocol", "allMatchedProtocols"]

TOP_N_PORTS = 10
TOP_N_DESTINATIONS = 10

# Active-hours robustness thresholds (see compute_device_profile)
MIN_FLOWS_PER_DAY = 50          # absolute floor -- days with fewer flows than this are always too noisy to trust
MIN_RELATIVE_FRACTION = 0.2     # additionally flag days below this fraction of the device's own median daily count
MAX_SINGLE_HOUR_SHARE = 0.5     # days this concentrated are likely truncated captures


# ---------------------------------------------------------------------------
# Device-name inference from filename
# ---------------------------------------------------------------------------

def extract_device_name(filename: str) -> str:
    """
    Turns a CSV filename into a device-type name, stripping common
    trailing date/index suffixes so that multiple daily files for the
    same device get grouped together.

    Adjust this function to match your actual filename convention if
    the defaults below don't fit (e.g. UNSW's per-day trace naming).
    """
    stem = Path(filename).stem

    # Strip trailing "-YYYY-MM-DD" or "_YYYY-MM-DD" date suffixes
    stem = re.sub(r"[-_]\d{4}-\d{2}-\d{2}$", "", stem)

    # Strip trailing "-day3", "_part2", "-2", etc.
    stem = re.sub(r"[-_](day|part)?\d+$", "", stem, flags=re.IGNORECASE)

    return stem


# ---------------------------------------------------------------------------
# Timestamp handling
# ---------------------------------------------------------------------------

def to_datetime_auto(series: pd.Series) -> pd.Series:
    """Best-effort conversion of a numeric epoch column to datetime,
    auto-detecting whether it's in seconds, milliseconds, or microseconds."""
    numeric = pd.to_numeric(series, errors="coerce")
    median_val = numeric.median()

    if pd.isna(median_val):
        return pd.to_datetime(series, errors="coerce")

    if median_val > 1e15:
        unit = "ns"
    elif median_val > 1e12:
        unit = "us"
    elif median_val > 1e10:
        unit = "ms"
    else:
        unit = "s"

    return pd.to_datetime(numeric, unit=unit, errors="coerce")


# ---------------------------------------------------------------------------
# Per-column distribution summary
# ---------------------------------------------------------------------------

def numeric_summary(series: pd.Series) -> dict:
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return {"count": 0}

    q1, median, q3 = s.quantile([0.25, 0.5, 0.75])
    return {
        "count": int(s.count()),
        "mean": float(s.mean()),
        "std": float(s.std()) if s.count() > 1 else 0.0,
        "median": float(median),
        "q1": float(q1),
        "q3": float(q3),
        "iqr": float(q3 - q1),
        "min": float(s.min()),
        "max": float(s.max()),
    }


def categorical_distribution(series: pd.Series, top_n: int = None) -> dict:
    s = series.dropna().astype(str)
    if s.empty:
        return {}
    counts = s.value_counts(normalize=True)
    if top_n:
        counts = counts.head(top_n)
    return {str(k): float(v) for k, v in counts.items()}


# ---------------------------------------------------------------------------
# Per-device calibration
# ---------------------------------------------------------------------------

def compute_device_profile(df_per_file: dict) -> dict:
    """
    df_per_file: {filename: dataframe} for all files belonging to one device.

    Kept separate per file (rather than pre-concatenated) specifically so
    the active-hours histogram can be computed robustly per day and then
    aggregated across days -- pooling all raw timestamps together lets a
    single truncated/anomalous day's flows sit undiluted in the pool,
    which produced a misleading single-hour spike in earlier testing.
    """
    combined = pd.concat(df_per_file.values(), ignore_index=True)
    profile = {"num_flows": len(combined), "num_files": len(df_per_file)}

    # --- numeric distributions (pooled across all files is fine here) ----
    profile["numeric_stats"] = {
        col: numeric_summary(combined[col]) for col in NUMERIC_COLS if col in combined.columns
    }

    # --- protocol / port distributions -----------------------------------
    profile["categorical_stats"] = {
        col: categorical_distribution(combined[col]) for col in CATEGORICAL_COLS if col in combined.columns
    }

    if "dstPort" in combined.columns:
        profile["top_dst_ports"] = categorical_distribution(combined["dstPort"], TOP_N_PORTS)

    if "srcPort" in combined.columns:
        profile["top_src_ports"] = categorical_distribution(combined["srcPort"], TOP_N_PORTS)

    # --- destination behavior --------------------------------------------
    if "dstIp" in combined.columns:
        dst = combined["dstIp"].dropna().astype(str)
        n_flows = len(dst)
        vc = dst.value_counts()
        profile["distinct_destination_count"] = int(vc.shape[0])
        profile["top_destinations"] = {
            str(k): float(v / n_flows) for k, v in vc.head(TOP_N_DESTINATIONS).items()
        } if n_flows else {}
        # "new destination" rate proxy: fraction of flows going to a destination
        # that appears only once in this device's whole capture
        singleton_dsts = (vc == 1).sum()
        profile["approx_new_destination_fraction"] = (
            float(singleton_dsts / n_flows) if n_flows else 0.0
        )

    # --- active hours: robust per-day-median aggregation ------------------
    if "time" in combined.columns:
        # First pass: compute each valid day's hour-of-day histogram and flow count,
        # so we can derive this device's own "typical day" volume before deciding
        # which days look anomalously sparse relative to *this* device.
        per_file_hours = {}
        for fname, df in df_per_file.items():
            if "time" not in df.columns:
                continue
            ts = to_datetime_auto(df["time"])
            hours = ts.dt.hour.dropna()
            if not hours.empty:
                per_file_hours[fname] = hours

        median_daily_flows = (
            float(np.median([len(h) for h in per_file_hours.values()]))
            if per_file_hours else 0.0
        )
        relative_floor = MIN_RELATIVE_FRACTION * median_daily_flows

        daily_hists = []
        excluded_files = []

        for fname, hours in per_file_hours.items():
            hist = hours.value_counts(normalize=True).reindex(range(24), fill_value=0.0)
            n_flows = len(hours)

            too_few_absolute = n_flows < MIN_FLOWS_PER_DAY
            too_few_relative = n_flows < relative_floor
            too_concentrated = hist.max() > MAX_SINGLE_HOUR_SHARE

            if too_few_absolute or too_few_relative or too_concentrated:
                excluded_files.append(fname)
                continue

            daily_hists.append(hist)

        if daily_hists:
            daily_matrix = pd.concat(daily_hists, axis=1)  # 24 rows x n_valid_days
            median_hist = daily_matrix.median(axis=1)
            full_hist = {str(h): float(median_hist.get(h, 0.0)) for h in range(24)}
            profile["active_hours_histogram"] = full_hist

            threshold = 1.0 / 48  # roughly half of a uniform 24-hour share
            profile["active_hours"] = [h for h in range(24) if full_hist[str(h)] >= threshold]
            profile["active_hours_median_daily_flows"] = median_daily_flows
            profile["active_hours_days_used"] = len(daily_hists)
            profile["active_hours_days_excluded"] = excluded_files
        else:
            profile["active_hours_histogram"] = {}
            profile["active_hours"] = []
            profile["active_hours_median_daily_flows"] = median_daily_flows
            profile["active_hours_days_used"] = 0
            profile["active_hours_days_excluded"] = excluded_files

    return profile


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Calibrate per-device traffic profiles from flow CSVs.")
    parser.add_argument("--folder", required=True, help="Folder containing the flow CSV files.")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output JSON file path (default: data/artifacts/traffic_generation/device_traffic_profiles.json).",
    )
    parser.add_argument("--pattern", default="*.csv", help="Glob pattern for CSV files (default: *.csv).")
    args = parser.parse_args()
    folder = Path(args.folder)
    csv_files = sorted(folder.glob(args.pattern))

    if not csv_files:
        print(f"No CSV files found in {folder} matching '{args.pattern}'")
        return

    # Group files by inferred device name
    device_files = defaultdict(list)
    for f in csv_files:
        device_name = extract_device_name(f.name)
        device_files[device_name].append(f)

    print(f"Found {len(csv_files)} files across {len(device_files)} inferred devices:")
    for device, files in device_files.items():
        print(f"  {device}: {len(files)} file(s)")

    all_profiles = {}
    for device, files in device_files.items():
        dfs_by_file = {}
        for f in files:
            try:
                dfs_by_file[f.name] = pd.read_csv(f, low_memory=False)
            except Exception as e:
                print(f"  [warn] failed to read {f}: {e}")
        if not dfs_by_file:
            continue

        total_flows = sum(len(df) for df in dfs_by_file.values())
        print(f"\nComputing profile for '{device}' ({total_flows} total flows across {len(dfs_by_file)} file(s))...")
        profile = compute_device_profile(dfs_by_file)
        all_profiles[device] = profile

        excluded = profile.get("active_hours_days_excluded", [])
        if excluded:
            print(f"  Excluded {len(excluded)} day(s) from active-hours calibration "
                  f"(too few flows or single-hour concentration): {excluded}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        json.dump(all_profiles, f, indent=2)

    print(f"\nSaved calibration profiles for {len(all_profiles)} devices to {args.out}")


if __name__ == "__main__":
    main()

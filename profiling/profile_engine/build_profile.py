"""
build_profile.py

The Profiling Engine's offline half: turns a device's per-window features
(from profiling/features/windows.py) plus its Zeek logs into one frozen
behavioural profile -- the automatically generated equivalent of a
hand-written MUD profile.

A profile has two halves, and they answer different questions:

  window_features -- robust statistics (median/IQR, 3-sigma trimming) for each
                     windowed feature. This is what a live deviation score is
                     measured against: "is this minute normal for this device?"

  endpoints       -- the allow-list actually observed: domains queried, TLS
                     server names, destination ports, destination IPs. This is
                     what the MUD ground-truth comparison scores against, and
                     what "the bulb contacted somewhere new" is judged by.

Outliers are excluded with a robust spread estimate (sigma ~ IQR/1.349) rather
than a standard deviation, because a standard deviation is itself dragged by
the outliers it is meant to exclude. A single 82MB firmware-update window must
not be allowed to redefine what a normal minute looks like. This is one of the
three poisoned-baseline defences: a compromise present during the learning
window shifts a trimmed median far less than it shifts a mean.

Once written, a profile is frozen. The live loop reads it and never updates it.

Usage:
    python profiling/profile_engine/build_profile.py \
        --windows data/processed/unsw/features/AmazonEcho/windows.jsonl \
        --zeek-dir data/processed/unsw/zeek/AmazonEcho \
        --device AmazonEcho_44650d56ccd3 \
        --out data/processed/unsw/behavioral_profiles/AmazonEcho.json
"""

import argparse
import json
import math
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# The repo runs scripts directly rather than as an installed package, so the
# sibling feature module is put on the path explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "features"))

from zeek_log import (  # noqa: E402
    device_ips,
    device_mac_from_name,
    read_conn,
    read_dns_queries,
    read_tls_server_names,
)

SCHEMA_VERSION = 1

# Ratio between the IQR and the standard deviation of a normal distribution.
# Used to get a spread estimate the outliers themselves cannot inflate.
IQR_TO_SIGMA = 1.349

# Windowed features that get robust statistics. Everything else in a window
# row is metadata (window_start, hour_of_day) or categorical
# (service_distribution) and is summarised separately.
NUMERIC_FEATURES = [
    "flow_count",
    "unique_destinations",
    "unique_domains",
    "domain_entropy",
    "bytes_total",
    "orig_bytes",
    "resp_bytes",
    "packets_total",
    "interflow_gap_variance",
    "tcp_failed_ratio",
]

# Features trimmed in log space. Traffic volume is heavy-tailed -- a device
# that normally sends 200 bytes a minute legitimately sends tens of megabytes
# during a firmware update or a media stream. Trimming those in linear space
# excluded 11% of the Echo's windows and cut its retained maximum from 83MB to
# 6KB, which would make every ordinary burst look anomalous at scoring time.
# In log space the same 3-sigma rule keeps the bursts and still excludes true
# outliers. Bounded features (entropy, ratios) are trimmed linearly: they have
# no tail to compress.
LOG_SCALE_FEATURES = {
    "flow_count",
    "unique_destinations",
    "unique_domains",
    "bytes_total",
    "orig_bytes",
    "resp_bytes",
    "packets_total",
    "interflow_gap_variance",
}


def percentile(sorted_values, fraction):
    """Nearest-rank percentile of an already-sorted, non-empty list."""
    index = max(0, min(len(sorted_values) - 1, int(round(fraction * (len(sorted_values) - 1)))))
    return sorted_values[index]


def quartiles(sorted_values):
    if len(sorted_values) < 2:
        only = sorted_values[0]
        return only, only
    q1, _median, q3 = statistics.quantiles(sorted_values, n=4, method="inclusive")
    return q1, q3


def robust_stats(values, log_scale=False):
    """Median/IQR summary of one feature, with 3-sigma outliers excluded.

    log_scale trims in log1p space (see LOG_SCALE_FEATURES) while all reported
    statistics stay in the feature's own units.

    Windows where the feature was not observed (None) are dropped rather than
    counted as zero: a window with two flows has no inter-flow spread, which
    is not the same fact as a spread of zero.

    Returns None when a feature was never observed at all.
    """
    observed = sorted(v for v in values if v is not None)
    if not observed:
        return None

    # Trimming happens in `space`; every reported statistic is computed on the
    # original values of the windows that survived.
    negative = observed[0] < 0
    use_log = log_scale and not negative
    space = [math.log1p(v) for v in observed] if use_log else observed

    median = statistics.median(space)
    q1, q3 = quartiles(space)
    iqr = q3 - q1

    # With no spread to estimate (a constant feature, common for quiet
    # devices) there is nothing to trim, and IQR/1.349 would be 0 -- which
    # would exclude every value that is not exactly the median.
    sigma = iqr / IQR_TO_SIGMA if iqr > 0 else None
    if sigma:
        low, high = median - 3 * sigma, median + 3 * sigma
        kept = [v for v, s in zip(observed, space) if low <= s <= high]
        if use_log:
            low, high = math.expm1(low), math.expm1(high)
    else:
        kept = observed
    if not kept:
        kept = observed

    kept_q1, kept_q3 = quartiles(kept)
    return {
        "median": statistics.median(kept),
        "q1": kept_q1,
        "q3": kept_q3,
        "iqr": kept_q3 - kept_q1,
        "mean": statistics.fmean(kept),
        "min": kept[0],
        "max": kept[-1],
        "p95": percentile(kept, 0.95),
        "p99": percentile(kept, 0.99),
        "windows_observed": len(observed),
        "windows_excluded": len(observed) - len(kept),
        "outlier_bounds": [low, high] if sigma else None,
        "trim_space": "log1p" if use_log else "linear",
    }


def summarise_services(windows):
    """Mean share per service label, and how often each label appears."""
    share_total = Counter()
    windows_present = Counter()
    for window in windows:
        for service, share in window.get("service_distribution", {}).items():
            share_total[service] += share
            windows_present[service] += 1

    count = len(windows) or 1
    return {
        service: {
            "mean_share": share_total[service] / count,
            "windows_present": windows_present[service],
            "window_share": windows_present[service] / count,
        }
        for service in sorted(share_total, key=share_total.get, reverse=True)
    }


def summarise_active_hours(windows):
    """Flow and window counts per UTC hour of day."""
    flows_by_hour = Counter()
    windows_by_hour = Counter()
    for window in windows:
        hour = window["hour_of_day"]
        flows_by_hour[hour] += window.get("flow_count", 0)
        windows_by_hour[hour] += 1

    total_flows = sum(flows_by_hour.values()) or 1
    total_windows = sum(windows_by_hour.values()) or 1
    return [
        {
            "hour": hour,
            "flows": flows_by_hour.get(hour, 0),
            "flow_share": flows_by_hour.get(hour, 0) / total_flows,
            "windows": windows_by_hour.get(hour, 0),
            "window_share": windows_by_hour.get(hour, 0) / total_windows,
        }
        for hour in range(24)
    ]


def collect_endpoints(zeek_dir, mac):
    """The device's observed allow-list: domains, TLS names, ports, IPs."""
    ips = device_ips(zeek_dir, mac)

    domains = Counter(query for _ts, query in read_dns_queries(zeek_dir, ips=ips))
    tls_names = Counter(read_tls_server_names(zeek_dir, ips=ips))

    ports = Counter()
    destinations = Counter()
    listening = Counter()
    sources = Counter()

    # Both directions are collected: MUD describes a device with a from-device
    # ACL and a to-device ACL, so a profile that only knows what the device
    # dialled out to cannot answer for half of the ground truth. The plug's
    # tcp/9999 control port, which the phone app connects *to*, appears
    # nowhere in its outbound flows.
    for record in read_conn(zeek_dir, mac=mac, initiated_only=False):
        proto, port = record.get("proto"), record.get("id.resp_p")
        if record.get("orig_l2_addr") == mac:
            destination = record.get("id.resp_h")
            if destination:
                destinations[destination] += 1
            if port is not None and proto:
                ports[f"{proto}/{port}"] += 1
        else:
            source = record.get("id.orig_h")
            if source:
                sources[source] += 1
            if port is not None and proto:
                listening[f"{proto}/{port}"] += 1

    return {
        "domains": dict(domains.most_common()),
        "tls_server_names": dict(tls_names.most_common()),
        "destination_ports": dict(ports.most_common()),
        "listening_ports": dict(listening.most_common()),
        "destination_ips": dict(destinations.most_common()),
        "source_ips": dict(sources.most_common()),
        "counts": {
            "domains": len(domains),
            "tls_server_names": len(tls_names),
            "destination_ports": len(ports),
            "listening_ports": len(listening),
            "destination_ips": len(destinations),
            "source_ips": len(sources),
        },
    }


def calibrate(profile, windows):
    """Record how each deviation component behaves on the device's own baseline.

    Without this, component values are not comparable: protocol_drift is
    non-zero for essentially every ordinary window, while a new destination is
    zero for all of them. The scorer uses these percentiles to express a
    component as "how far beyond normal", so the same threshold means the same
    thing across components and across devices.

    Computed from the training windows only, and frozen with the profile.
    """
    from score_window import calibrate_components, combine, raw_components

    collected = {}
    for window in windows:
        components, _evidence = raw_components(profile, window)
        for name, value in components.items():
            collected.setdefault(name, []).append(value)

    component_stats = {}
    for name, values in collected.items():
        values.sort()
        component_stats[name] = {
            "p50": percentile(values, 0.50),
            "p95": percentile(values, 0.95),
            "p99": percentile(values, 0.99),
        }

    # Score the baseline again, now calibrated, so the profile carries the
    # score distribution the Decision Engine's thresholds should be read from.
    scores = sorted(
        combine(calibrate_components(raw_components(profile, window)[0], component_stats))
        for window in windows
    )
    return {
        "components": component_stats,
        "baseline_scores": {
            "p50": percentile(scores, 0.50),
            "p95": percentile(scores, 0.95),
            "p99": percentile(scores, 0.99),
            "max": scores[-1],
            "windows": len(scores),
        },
    }


def build_profile(windows, zeek_dir, device, mac, source_note=None):
    starts = [w["window_start"] for w in windows]
    window_seconds = windows[0].get("window_seconds")

    profile = {
        "schema_version": SCHEMA_VERSION,
        "device": device,
        "mac": mac,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frozen": True,
        "source": {
            "zeek_dir": str(zeek_dir),
            "window_seconds": window_seconds,
            "note": source_note,
        },
        "observation": {
            "active_windows": len(windows),
            "flows": sum(w.get("flow_count", 0) for w in windows),
            "first_window": min(starts),
            "last_window": max(starts),
            "span_days": (max(starts) - min(starts)) / 86400,
        },
        "window_features": {
            feature: robust_stats(
                [w.get(feature) for w in windows],
                log_scale=feature in LOG_SCALE_FEATURES,
            )
            for feature in NUMERIC_FEATURES
        },
        "service_distribution": summarise_services(windows),
        "active_hours": summarise_active_hours(windows),
        "endpoints": collect_endpoints(zeek_dir, mac),
    }

    # Calibration runs last: it scores the training windows against the
    # profile that has just been assembled.
    profile["calibration"] = calibrate(profile, windows)
    return profile


def main():
    parser = argparse.ArgumentParser(
        description="Build a frozen behavioural profile for one device."
    )
    parser.add_argument("--windows", required=True, type=Path,
                        help="Per-window features JSONL from windows.py.")
    parser.add_argument("--zeek-dir", required=True, type=Path,
                        help="That device's Zeek log directory (for endpoints).")
    parser.add_argument("--device", required=True,
                        help="Device name, e.g. AmazonEcho_44650d56ccd3.")
    parser.add_argument("--mac", default=None,
                        help="Override the MAC inferred from --device.")
    parser.add_argument("--note", default=None,
                        help="Free-text provenance note stored in the profile.")
    parser.add_argument("--out", required=True, type=Path,
                        help="Output profile JSON path.")
    args = parser.parse_args()

    mac = args.mac or device_mac_from_name(args.device)
    if mac is None:
        raise SystemExit(
            f"Could not infer a MAC from '{args.device}' -- pass --mac explicitly."
        )

    with args.windows.open() as handle:
        windows = [json.loads(line) for line in handle if line.strip()]
    if not windows:
        raise SystemExit(f"No windows in {args.windows}")

    profile = build_profile(windows, args.zeek_dir, args.device, mac, args.note)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as handle:
        json.dump(profile, handle, indent=2)

    features = profile["window_features"]
    endpoints = profile["endpoints"]["counts"]
    flow = features["flow_count"]
    print(
        f"{args.device}: {profile['observation']['active_windows']} windows over "
        f"{profile['observation']['span_days']:.0f} days | "
        f"flows/window median={flow['median']:.1f} (q1={flow['q1']:.1f} q3={flow['q3']:.1f}, "
        f"{flow['windows_excluded']} outlier windows trimmed) | "
        f"{endpoints['domains']} domains, {endpoints['destination_ports']} ports, "
        f"{endpoints['destination_ips']} IPs -> {args.out}"
    )


if __name__ == "__main__":
    main()

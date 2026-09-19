"""
windows.py

Aggregates a device's Zeek flows into fixed-length time windows and computes
the per-window behavioural features the Profiling Engine builds its baseline
from.

The window length matches the live detection loop (60s), so a window computed
here from a 2016 UNSW replay and a window computed live in Mininet are the
same kind of object, and a frozen profile stays meaningful against live input.

Ten features per window:

  1.  flow_count             flows the device initiated
  2.  unique_destinations    distinct destination IPs
  3.  unique_domains         distinct domains queried (dns.log)
  4.  domain_entropy         Shannon entropy (bits) over queried domains
  5.  bytes_total            orig_bytes + resp_bytes
  6.  packets_total          orig_pkts + resp_pkts
  7.  service_distribution   share per Zeek service label ("unknown" if none)
  8.  interflow_gap_variance variance of gaps between consecutive flows (s)
  9.  tcp_failed_ratio       share of TCP flows whose handshake never completed
  10. hour_of_day            UTC hour, feeding the active-hour histogram

Windows with no activity are not emitted: a months-long capture is mostly
idle, and an explicit row per silent minute would be almost all of the output.
The profile builder treats absent windows as silence.

Usage:
    python profiling/features/windows.py \
        --zeek-dir data/processed/unsw/zeek/AmazonEcho \
        --device AmazonEcho_44650d56ccd3 \
        --out data/processed/unsw/features/AmazonEcho/windows.jsonl
"""

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from zeek_log import (
    TCP_FAILED_STATES,
    device_ips,
    device_mac_from_name,
    read_conn,
    read_dns_queries,
)

DEFAULT_WINDOW_SECONDS = 60

# conn.log fields the window features actually read.
FEATURE_FIELDS = (
    "ts",
    "id.resp_h",
    "proto",
    "service",
    "conn_state",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
)


def shannon_entropy(counter):
    """Shannon entropy in bits over the values of a Counter."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    # The trailing + 0.0 normalises the -0.0 that a single-domain window
    # would otherwise produce, so profiles and logs read cleanly.
    return -sum(
        (n / total) * math.log2(n / total)
        for n in counter.values()
        if n > 0
    ) + 0.0


def bucket_flows(zeek_dir, mac, window_seconds):
    """Group a device's flows and DNS queries into window buckets."""
    flows = defaultdict(list)
    domains = defaultdict(Counter)

    # Only the fields the features need are retained. The full Zeek record has
    # 22 columns, and the busiest UNSW capture holds 1.1M flows -- keeping
    # whole records would cost gigabytes for data that is then ignored.
    for record in read_conn(zeek_dir, mac=mac):
        ts = record.get("ts")
        if ts is None:
            continue
        flows[int(ts // window_seconds)].append(
            {field: record.get(field) for field in FEATURE_FIELDS}
        )

    # dns.log carries no MAC columns, so the device is identified there by the
    # IPs it originated conn.log flows from.
    for ts, query in read_dns_queries(zeek_dir, ips=device_ips(zeek_dir, mac)):
        domains[int(ts // window_seconds)][query] += 1

    return flows, domains


def window_features(bucket, records, domain_counts, window_seconds):
    """Compute the ten features for one window."""
    start = bucket * window_seconds
    timestamps = sorted(r["ts"] for r in records if r.get("ts") is not None)

    # Inter-flow timing: variance of the gaps between consecutive flows.
    # Needs at least three flows to give two gaps; below that it is not a
    # spread, and reporting 0.0 would look like perfect regularity.
    gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
    gap_variance = statistics.pvariance(gaps) if len(gaps) >= 2 else None

    # TCP only: UDP flows are logged S0 whenever the capture holds no reply,
    # which would drown the signal this feature exists to carry.
    tcp = [r for r in records if r.get("proto") == "tcp"]
    tcp_failed = sum(1 for r in tcp if r.get("conn_state") in TCP_FAILED_STATES)

    services = Counter(r.get("service") or "unknown" for r in records)
    total_services = sum(services.values())

    def total(field):
        return sum(r.get(field) or 0 for r in records)

    # Endpoint lists are carried on the window itself: the deviation scorer
    # has to know which destination is new, not just how many there were, and
    # the live graph builder needs the same edges.
    destinations = sorted({r.get("id.resp_h") for r in records if r.get("id.resp_h")})
    ports = sorted({
        f"{r['proto']}/{r['id.resp_p']}"
        for r in records
        if r.get("proto") and r.get("id.resp_p") is not None
    })

    return {
        "window_start": start,
        "window_seconds": window_seconds,
        "hour_of_day": datetime.fromtimestamp(start, timezone.utc).hour,
        "flow_count": len(records),
        "unique_destinations": len(destinations),
        "unique_domains": len(domain_counts),
        "domain_entropy": shannon_entropy(domain_counts),
        "bytes_total": total("orig_bytes") + total("resp_bytes"),
        "orig_bytes": total("orig_bytes"),
        "resp_bytes": total("resp_bytes"),
        "packets_total": total("orig_pkts") + total("resp_pkts"),
        "service_distribution": {
            name: count / total_services for name, count in services.items()
        } if total_services else {},
        "interflow_gap_variance": gap_variance,
        "tcp_failed_ratio": (tcp_failed / len(tcp)) if tcp else None,
        "destinations": destinations,
        "destination_ports": ports,
        "domains": sorted(domain_counts),
    }


def build_windows(zeek_dir, mac, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Yield per-window feature dicts in chronological order."""
    flows, domains = bucket_flows(zeek_dir, mac, window_seconds)
    for bucket in sorted(set(flows) | set(domains)):
        yield window_features(
            bucket, flows.get(bucket, []), domains.get(bucket, Counter()), window_seconds
        )


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate a device's Zeek logs into per-window features."
    )
    parser.add_argument("--zeek-dir", required=True, type=Path,
                        help="Directory holding conn.log/dns.log for one device.")
    parser.add_argument("--device", required=True,
                        help="Device name, e.g. AmazonEcho_44650d56ccd3. The MAC "
                             "suffix is used to identify the device.")
    parser.add_argument("--mac", default=None,
                        help="Override the MAC inferred from --device.")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS,
                        help="Window length in seconds (default: 60).")
    parser.add_argument("--out", type=Path, default=None,
                        help="Output JSONL path. Omit to print a summary only.")
    args = parser.parse_args()

    mac = args.mac or device_mac_from_name(args.device)
    if mac is None:
        raise SystemExit(
            f"Could not infer a MAC from '{args.device}' -- pass --mac explicitly."
        )

    windows = list(build_windows(args.zeek_dir, mac, args.window))
    if not windows:
        raise SystemExit(f"No flows found for {args.device} ({mac}) in {args.zeek_dir}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w") as handle:
            for window in windows:
                handle.write(json.dumps(window) + "\n")

    span_days = (windows[-1]["window_start"] - windows[0]["window_start"]) / 86400
    flows = sum(w["flow_count"] for w in windows)
    print(
        f"{args.device} ({mac}): {len(windows)} active windows, {flows} flows, "
        f"{span_days:.0f} days"
        + (f" -> {args.out}" if args.out else "")
    )


if __name__ == "__main__":
    main()

"""
score_window.py

The Profiling Engine's live half: given a device's frozen profile and one 60s
window of its current traffic, how far outside its own normal is it?

This is inference only. The profile is never updated from what it scores --
that separation is what keeps the "learned automatically, not from the
simulation" claim honest, and it is why a compromised device cannot quietly
teach the system that its new behaviour is normal.

Seven components, each in [0.0, 1.0], each reported separately so a flagged
window can be explained ("three destinations it has never contacted") rather
than asserted:

  new_destinations  share of this window's destination IPs never seen before
  new_domains       share of queried domains never seen before
  new_ports         share of proto/port pairs never seen before
  volume            how far bytes_total sits above the device's usual
  flow_rate         how far flow_count sits above the device's usual
  protocol_drift    how far the service mix has moved from the baseline mix
  failed_conns      TCP failures above the baseline's ceiling (scan signal)

Deviations are one-sided: a quiet device is not an anomalous device, so only
excursions *above* the baseline score. Magnitudes are robust z-scores --
(value - median) / (IQR / 1.349) -- computed in the same space the profile was
trimmed in. Quantiles commute with log1p, so a log-scale feature's median and
IQR can be moved into log space exactly.

The seven are combined with a noisy-or, so several mild signals can add up to
a meaningful score while any single strong signal is enough on its own. The
combined number is a deviation score, not a verdict: it is one of the inputs
the Decision Engine fuses with the GNN's signals before choosing a response.

Usage:
    python profiling/profile_engine/score_window.py \
        --profile data/processed/unsw/behavioral_profiles/AmazonEcho.json \
        --windows data/processed/unsw/features/AmazonEcho/windows.jsonl \
        --out data/processed/unsw/scores/AmazonEcho.jsonl
"""

import argparse
import json
import math
from pathlib import Path

IQR_TO_SIGMA = 1.349

# Robust z that scores 0.5. Six robust sigmas above the median is well outside
# a stable baseline, while leaving ordinary bursts scoring partially.
#
# The mapping z -> z/(z + Z_HALF) is deliberately smooth and never reaches 1.0.
# A hard cap (min(1, z/6)) interacts badly with percentile calibration: on
# quiet devices with a narrow IQR, more than 1% of perfectly normal windows
# reach the cap, the calibrated ceiling becomes 1.0, the headroom becomes zero,
# and the component is silently dead forever. Four devices lost their volume
# component that way, and a 500MB exfiltration window scored on endpoint
# novelty alone.
Z_HALF = 6.0

# Highest calibrated ceiling allowed, so every component keeps some headroom.
MAX_CEILING = 0.99

# Components that read a numeric feature, and whether the profile trims that
# feature in log space (mirrored from build_profile.LOG_SCALE_FEATURES).
NUMERIC_COMPONENTS = {
    "volume": "bytes_total",
    "flow_rate": "flow_count",
}


def clip01(value):
    return max(0.0, min(1.0, value))


def robust_z(value, stats):
    """One-sided robust z-score of `value` against a profile feature.

    Returns 0.0 when the value is at or below the baseline median: this
    detector is looking for excursions, not quiet.
    """
    if value is None or stats is None:
        return 0.0

    log_space = stats.get("trim_space") == "log1p" and value >= 0
    transform = (lambda x: math.log1p(x)) if log_space else (lambda x: x)

    # Quantiles commute with a monotone transform, so the profile's median and
    # quartiles can be moved into log space directly.
    median = transform(stats["median"])
    spread = (transform(stats["q3"]) - transform(stats["q1"])) / IQR_TO_SIGMA
    current = transform(value)

    if current <= median:
        return 0.0

    if spread <= 0:
        # A constant baseline has no spread to measure against, so deviation is
        # expressed as how far past the highest value ever seen this is.
        ceiling = transform(stats["max"])
        if current <= ceiling or ceiling <= 0:
            return 0.0
        return Z_HALF * (current / ceiling)

    return (current - median) / spread


def squash(z):
    """Map a non-negative robust z into [0, 1), reaching 0.5 at Z_HALF."""
    return z / (z + Z_HALF) if z > 0 else 0.0


def unseen_share(observed, known):
    """Share of this window's items that the profile has never seen."""
    if not observed:
        return 0.0, []
    new = sorted(set(observed) - set(known))
    return len(new) / len(observed), new


def protocol_drift(window, profile):
    """Total variation distance between this window's service mix and the baseline.

    TVD is in [0, 1] already and needs no squashing: 0 is an identical mix, 1
    means the window shares no service with the baseline at all.
    """
    baseline = {
        service: stats["mean_share"]
        for service, stats in profile.get("service_distribution", {}).items()
    }
    total = sum(baseline.values())
    if total <= 0:
        return 0.0
    baseline = {k: v / total for k, v in baseline.items()}

    current = window.get("service_distribution") or {}
    services = set(baseline) | set(current)
    return 0.5 * sum(abs(current.get(s, 0.0) - baseline.get(s, 0.0)) for s in services)


def failed_conn_score(window, profile):
    """TCP failures above the baseline's ceiling.

    Scored against p99 rather than the median: a couple of failed connections
    is normal for any device, and what matters is a window where most
    attempts fail -- the signature of a port scan.
    """
    ratio = window.get("tcp_failed_ratio")
    stats = profile["window_features"].get("tcp_failed_ratio")
    if ratio is None or stats is None:
        return 0.0
    ceiling = stats.get("p99")
    if ceiling is None or ratio <= ceiling:
        return 0.0
    headroom = 1.0 - ceiling
    return clip01((ratio - ceiling) / headroom) if headroom > 0 else 0.0


def raw_components(profile, window):
    """Component values before calibration, plus the evidence behind them."""
    endpoints = profile["endpoints"]
    features = profile["window_features"]

    dest_share, new_dests = unseen_share(
        window.get("destinations", []), endpoints["destination_ips"]
    )
    domain_share, new_domains = unseen_share(
        window.get("domains", []),
        set(endpoints["domains"]) | set(endpoints["tls_server_names"]),
    )
    port_share, new_ports = unseen_share(
        window.get("destination_ports", []),
        set(endpoints["destination_ports"]) | set(endpoints.get("listening_ports", {})),
    )

    components = {
        "new_destinations": dest_share,
        "new_domains": domain_share,
        "new_ports": port_share,
        "protocol_drift": protocol_drift(window, profile),
        "failed_conns": failed_conn_score(window, profile),
    }
    for name, feature in NUMERIC_COMPONENTS.items():
        components[name] = squash(robust_z(window.get(feature), features.get(feature)))

    evidence = {
        "new_destinations": new_dests[:20],
        "new_domains": new_domains[:20],
        "new_ports": new_ports[:20],
    }
    return components, evidence


def calibrate_components(components, calibration):
    """Rescale raw components against how they behave on normal traffic.

    A raw component is not comparable across devices or across components.
    protocol_drift in particular is non-zero for every ordinary window: a
    single minute holding only DNS and NTP differs from the device's average
    service mix, which is normal rather than suspicious. Scoring that raw
    flagged ~43% of the Amazon Echo's own training windows.

    So each component is measured against its own baseline distribution: only
    the part of a value that exceeds the 99th percentile of normal counts, and
    that excess is stretched over the remaining headroom. By construction
    roughly 1% of baseline windows put any given component above zero.
    """
    if not calibration:
        return dict(components)

    scaled = {}
    for name, value in components.items():
        # The ceiling is capped below 1.0 so a component can never be scaled
        # out of existence. The share-type components (new_destinations and
        # friends) are naturally bounded, and a device that churns endpoints
        # every minute -- an NTP pool rotation, say -- can legitimately have a
        # p99 at or near 1.0. Such a component should be weak evidence for
        # that device, not permanently silent.
        ceiling = min(calibration.get(name, {}).get("p99", 0.0), MAX_CEILING)
        headroom = 1.0 - ceiling
        scaled[name] = clip01((value - ceiling) / headroom)
    return scaled


def combine(components):
    """Noisy-or: independent evidence accumulates, one strong signal suffices."""
    remaining = 1.0
    for value in components.values():
        remaining *= (1.0 - value)
    return 1.0 - remaining


def score_window(profile, window):
    """Score one window against a frozen profile."""
    raw, evidence = raw_components(profile, window)
    calibration = (profile.get("calibration") or {}).get("components")
    components = calibrate_components(raw, calibration)
    score = combine(components)

    top = max(components, key=components.get)
    return {
        "window_start": window.get("window_start"),
        "device": profile["device"],
        "deviation_score": score,
        "components": components,
        "raw_components": raw,
        "top_component": top if components[top] > 0 else None,
        "evidence": evidence,
        "calibrated": bool(calibration),
    }


def suggest_tiers(profile):
    """Per-device score thresholds for the Decision Engine's four response tiers.

    The Decision Engine picks one of: alert only, rate-limit, VLAN isolate,
    full block. It needs a cut-off for each, and one global set of numbers does
    not fit every device: the Amazon Echo's baseline p99 is 0.030 while iHome's
    is 1.000, so a score of 0.6 is extraordinary for one device and an ordinary
    Tuesday for the other.

    Each profile carries what is needed to set these from data:

        profile["calibration"]["baseline_scores"]  -> p50, p95, p99, max
        (measured on the device's own normal traffic, where every flag is
        by definition a false alarm)

    Returns a dict like {"alert": 0.4, "rate_limit": 0.6, "isolate": 0.8,
    "block": 0.95} with thresholds in increasing order.
    """
    # TODO(human): decide how the four tier thresholds are derived from
    # baseline_scores, and return them.
    raise NotImplementedError


def load_profile(path):
    profile = json.loads(Path(path).read_text())
    if not profile.get("frozen"):
        raise SystemExit(f"{path} is not marked frozen -- refusing to score against it.")
    return profile


def main():
    parser = argparse.ArgumentParser(
        description="Score windows against a device's frozen behavioural profile."
    )
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--windows", required=True, type=Path,
                        help="Window features JSONL to score.")
    parser.add_argument("--out", type=Path, default=None,
                        help="Write per-window scores here as JSONL.")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Score above which a window is counted as flagged.")
    parser.add_argument("--top", type=int, default=5,
                        help="How many highest-scoring windows to print.")
    args = parser.parse_args()

    profile = load_profile(args.profile)
    with args.windows.open() as handle:
        windows = [json.loads(line) for line in handle if line.strip()]

    scores = [score_window(profile, window) for window in windows]

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w") as handle:
            for entry in scores:
                handle.write(json.dumps(entry) + "\n")

    values = sorted(s["deviation_score"] for s in scores)
    flagged = [s for s in scores if s["deviation_score"] > args.threshold]
    median = values[len(values) // 2] if values else 0.0
    p99 = values[int(0.99 * (len(values) - 1))] if values else 0.0

    print(f"{profile['device']}: {len(scores)} windows scored")
    print(f"  median={median:.3f}  p99={p99:.3f}  max={values[-1]:.3f}")
    print(f"  flagged (> {args.threshold}): {len(flagged)} ({len(flagged) / len(scores):.2%})")
    for entry in sorted(scores, key=lambda s: -s["deviation_score"])[:args.top]:
        drivers = ", ".join(
            f"{k}={v:.2f}" for k, v in sorted(entry["components"].items(), key=lambda kv: -kv[1])
            if v > 0
        )
        print(f"    {entry['window_start']} score={entry['deviation_score']:.3f}  {drivers}")
    if args.out:
        print(f"  -> {args.out}")


if __name__ == "__main__":
    main()

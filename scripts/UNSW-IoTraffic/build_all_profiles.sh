#!/usr/bin/env bash
# build_all_profiles.sh
#
# Runs the Stage 0 offline pipeline over every UNSW-IoTraffic device capture:
#
#   pcap --(zeek -r, mac-logging)--> conn.log/dns.log/ssl.log/x509.log
#        --(windows.py)-----------> 60s window features
#        --(build_profile.py)-----> frozen behavioural profile
#
# and then scores every profile against the MUDgee ground truth (Objective 1).
#
# Zeek replays are skipped when logs already exist, so re-running is cheap.
# Set FORCE=1 to redo them.
#
# Usage:
#   bash scripts/UNSW-IoTraffic/build_all_profiles.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PCAPS="$ROOT/data/downloaded/UNSW/pcaps"
ZEEK_DIR="$ROOT/data/processed/unsw/zeek"
FEATURE_DIR="$ROOT/data/processed/unsw/features"
PROFILE_DIR="$ROOT/data/processed/unsw/profiles"
REPORT="$ROOT/data/processed/unsw/objective1_report.json"

ok=0
failed=()

for pcap in "$PCAPS"/*.pcap "$PCAPS"/*.pcapng; do
    [ -e "$pcap" ] || continue
    base="$(basename "$pcap")"
    stem="${base%.*}"          # AmazonEcho_44650d56ccd3
    name="${stem%%_*}"         # AmazonEcho

    echo "=== $name  ($(du -h "$pcap" | cut -f1))  $(date +%T)"

    if [ -s "$ZEEK_DIR/$name/conn.log" ] && [ -z "${FORCE:-}" ]; then
        echo "    zeek: cached"
    else
        mkdir -p "$ZEEK_DIR/$name"
        # -C disables checksum validation. Several UNSW captures were taken on
        # a NIC doing checksum offloading, so the checksums on the wire are
        # wrong by construction and Zeek would silently discard those packets
        # -- which for an IoT device is mostly its DNS and NTP traffic.
        if ! ( cd "$ZEEK_DIR/$name" && rm -f ./*.log && \
               zeek -C -r "$pcap" policy/protocols/conn/mac-logging ); then
            echo "    FAILED: zeek"
            failed+=("$name:zeek")
            continue
        fi
    fi

    if ! python3 "$ROOT/profiling/features/windows.py" \
            --zeek-dir "$ZEEK_DIR/$name" \
            --device "$stem" \
            --out "$FEATURE_DIR/$name/windows.jsonl"; then
        echo "    FAILED: windows"
        failed+=("$name:windows")
        continue
    fi

    if ! python3 "$ROOT/profiling/profile_engine/build_profile.py" \
            --windows "$FEATURE_DIR/$name/windows.jsonl" \
            --zeek-dir "$ZEEK_DIR/$name" \
            --device "$stem" \
            --note "UNSW-IoTraffic offline replay (Stage 0)" \
            --out "$PROFILE_DIR/$name.json"; then
        echo "    FAILED: profile"
        failed+=("$name:profile")
        continue
    fi

    ok=$((ok + 1))
done

echo
echo "=== profiles built: $ok   failed: ${#failed[@]} ${failed[*]:-}"
echo

python3 "$ROOT/profiling/validation/compare_mud.py" \
    --profiles "$PROFILE_DIR" \
    --mud-dir "$ROOT/data/mud_profiles" \
    --out "$REPORT"

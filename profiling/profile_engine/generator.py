"""Generate RFC 8520-shaped profiles from observed packet metadata.

The generator deliberately has no knowledge of the MUDgee reference corpus. It
learns a whitelist from packet headers, DNS answers, and robust per-window
traffic statistics. Reference profiles are consumed only by validation after
generated profiles have been written.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import pickle
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

WINDOW_SECONDS = 300
CACHE_VERSION = 1
CONTROL_PORTS = {53, 67, 68, 123, 1900, 5353, 5355}
MAC_SUFFIX_RE = re.compile(r"_([0-9a-fA-F]{12})$")


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower()) or "device"


def _mac_from_filename(path: Path) -> str | None:
    match = MAC_SUFFIX_RE.search(path.stem)
    if not match:
        return None
    raw = match.group(1).lower()
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2))


def _device_name(path: Path) -> str:
    match = MAC_SUFFIX_RE.search(path.stem)
    return path.stem[: match.start()] if match else path.stem


def _decode_name(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    return str(value).strip().rstrip(".").lower()


def _port(layer: Any, attribute: str) -> int | None:
    try:
        value = int(getattr(layer, attribute))
    except (AttributeError, TypeError, ValueError):
        return None
    return value if 0 <= value <= 65535 else None


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    fraction = position - lower
    return float(ordered[lower] * (1 - fraction) + ordered[upper] * fraction)


def _robust_summary(values: Iterable[int]) -> dict[str, float]:
    samples = [float(value) for value in values] or [0.0]
    q1 = _percentile(samples, 0.25)
    q3 = _percentile(samples, 0.75)
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    filtered = [value for value in samples if lower <= value <= upper] or samples
    median = statistics.median(filtered)
    mean = statistics.fmean(filtered)
    stdev = statistics.pstdev(filtered) if len(filtered) > 1 else 0.0
    return {
        "median": round(median, 3),
        "iqr": round(iqr, 3),
        "mean": round(mean, 3),
        "stddev": round(stdev, 3),
        "upper_3sigma": round(mean + 3 * stdev, 3),
    }


@dataclass(frozen=True, order=True)
class RuleKey:
    direction: str
    family: str
    protocol: int | str
    remote_ip: str | None
    remote_port: int | None
    port_role: str = "remote"
    ethertype: str | None = None


@dataclass
class RuleStats:
    packets: int = 0
    bytes: int = 0
    windows: Counter[int] = field(default_factory=Counter)

    def observe(self, packet_length: int, window: int) -> None:
        self.packets += 1
        self.bytes += packet_length
        self.windows[window] += 1

    def merge(self, other: "RuleStats") -> None:
        self.packets += other.packets
        self.bytes += other.bytes
        self.windows.update(other.windows)


@dataclass
class CaptureModel:
    pcap: Path
    device_name: str
    device_mac: str
    dns_by_ip: dict[str, set[str]]
    rules: dict[RuleKey, RuleStats]
    start_time: float
    end_time: float
    packet_count: int


def _dns_answers(packet: Any, dns_by_ip: dict[str, set[str]]) -> None:
    from scapy.layers.dns import DNS, DNSRR

    if DNS not in packet or int(packet[DNS].ancount or 0) <= 0:
        return
    dns = packet[DNS]
    query_names: set[str] = set()
    for index in range(int(dns.qdcount or 0)):
        try:
            query_name = _decode_name(dns.qd[index].qname)
        except (AttributeError, IndexError, TypeError):
            continue
        if query_name:
            query_names.add(query_name)
    for index in range(int(dns.ancount)):
        try:
            answer = dns.an[index]
        except (IndexError, TypeError):
            continue
        if not isinstance(answer, DNSRR) or int(answer.type) not in {1, 28}:
            continue
        name = _decode_name(answer.rrname)
        address = _decode_name(answer.rdata)
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            continue
        if name:
            dns_by_ip[address].add(name)
            # The query name is the service name the device actually selected.
            # A/AAAA owners may instead be CDN or load-balancer CNAME targets.
            dns_by_ip[address].update(query_names)


def _network_fields(packet: Any, direction: str) -> tuple[str, int, str | None, int | None, str]:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if IP in packet:
        layer = packet[IP]
        family = "ipv4"
        protocol = int(layer.proto)
        remote_ip = str(layer.dst if direction == "from-device" else layer.src)
    elif IPv6 in packet:
        layer = packet[IPv6]
        family = "ipv6"
        protocol = int(layer.nh)
        remote_ip = str(layer.dst if direction == "from-device" else layer.src)
    else:
        return "ethernet", 0, None, None, "remote"

    remote_port = None
    port_role = "remote"
    if TCP in packet:
        protocol = 6
        tcp = packet[TCP]
        remote_port = _port(tcp, "dport" if direction == "from-device" else "sport")
        try:
            local_peer = ipaddress.ip_address(remote_ip).is_private or ipaddress.ip_address(remote_ip).is_link_local
        except ValueError:
            local_peer = False
        if local_peer:
            # For a LAN client connecting to an IoT management service, the
            # peer port is ephemeral. The stable behavior is the device-side
            # listening port, in both packet directions.
            remote_port = _port(tcp, "sport" if direction == "from-device" else "dport")
            port_role = "device"
    elif UDP in packet:
        protocol = 17
        remote_port = _port(packet[UDP], "dport" if direction == "from-device" else "sport")
    elif ICMP in packet:
        protocol = 1
    return family, protocol, remote_ip, remote_port, port_role


def profile_pcap(pcap: str | Path, *, device_mac: str | None = None) -> CaptureModel:
    """Stream a capture into a compact, per-device statistical model."""

    path = Path(pcap)
    device_mac = (device_mac or _mac_from_filename(path) or "").lower()
    if not device_mac:
        raise ValueError(f"Cannot infer device MAC from {path.name}; pass device_mac explicitly")

    if path.suffix.lower() in {".pcap", ".pcapng"}:
        from .fast_capture import profile_pcap_fast

        return profile_pcap_fast(
            path,
            device_mac,
            _device_name(path),
            RuleKey,
            RuleStats,
            CaptureModel,
            WINDOW_SECONDS,
        )

    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.l2 import ARP, Ether
    from scapy.utils import PcapReader

    dns_by_ip: dict[str, set[str]] = defaultdict(set)
    rules: dict[RuleKey, RuleStats] = defaultdict(RuleStats)
    start_time = float("inf")
    end_time = float("-inf")
    packet_count = 0

    with PcapReader(str(path)) as reader:
        for packet in reader:
            if Ether not in packet:
                continue
            ethernet = packet[Ether]
            source = str(ethernet.src).lower()
            destination = str(ethernet.dst).lower()
            if source == device_mac:
                direction = "from-device"
            elif destination == device_mac:
                direction = "to-device"
            else:
                continue

            timestamp = float(packet.time)
            start_time = min(start_time, timestamp)
            end_time = max(end_time, timestamp)
            packet_count += 1
            _dns_answers(packet, dns_by_ip)

            family, protocol, remote_ip, remote_port, port_role = _network_fields(packet, direction)
            ethertype = None
            if family == "ethernet":
                ethertype = f"0x{int(ethernet.type):04x}"
                if ARP in packet:
                    protocol = "arp"
                elif BOOTP in packet or DHCP in packet:
                    protocol = "dhcp"
            window = int(timestamp // WINDOW_SECONDS)
            key = RuleKey(
                direction=direction,
                family=family,
                protocol=protocol,
                remote_ip=remote_ip,
                remote_port=remote_port,
                port_role=port_role,
                ethertype=ethertype,
            )
            rules[key].observe(len(packet), window)

    if not packet_count:
        raise ValueError(f"No Ethernet packets for {device_mac} found in {path}")
    return CaptureModel(
        pcap=path,
        device_name=_device_name(path),
        device_mac=device_mac,
        dns_by_ip=dict(dns_by_ip),
        rules=dict(rules),
        start_time=start_time,
        end_time=end_time,
        packet_count=packet_count,
    )


def _endpoint_matches(key: RuleKey, model: CaptureModel) -> tuple[dict[str, Any], dict[str, Any]]:
    mud: dict[str, Any] = {}
    network: dict[str, Any] = {"protocol": key.protocol}
    if key.port_role == "gateway":
        mud["controller"] = "urn:ietf:params:mud:gateway"
        return mud, network
    if not key.remote_ip:
        return mud, network

    port = key.remote_port
    direction_prefix = "dst" if key.direction == "from-device" else "src"
    names = sorted(model.dns_by_ip.get(key.remote_ip, ()), key=lambda item: (item.count("."), len(item), item))
    address = ipaddress.ip_address(key.remote_ip)

    is_local = address.is_private or address.is_link_local
    is_multicast_or_broadcast = address.is_multicast or (
        address.version == 4 and str(address) == "255.255.255.255"
    )

    if is_multicast_or_broadcast:
        suffix = 32 if address.version == 4 else 128
        network[f"{direction_prefix}-{key.family}-network"] = f"{address}/{suffix}"
        mud["local-networks"] = [None]
    elif port == 53 and is_local:
        mud["controller"] = "urn:ietf:params:mud:dns"
    elif port in {67, 68} and key.direction == "to-device":
        mud["controller"] = "urn:ietf:params:mud:gateway"
    elif names and not is_local:
        network[f"ietf-acldns:{direction_prefix}-dnsname"] = names[0]
    elif is_local:
        mud["local-networks"] = [None]
    else:
        suffix = 32 if address.version == 4 else 128
        network[f"{direction_prefix}-{key.family}-network"] = f"{address}/{suffix}"
    return mud, network


def _ace(key: RuleKey, model: CaptureModel, name: str) -> dict[str, Any]:
    matches: dict[str, Any] = {}
    if key.family == "ethernet":
        matches["ietf-mud:mud"] = {"local-networks": [None]}
        matches["eth"] = {"ethertype": key.ethertype}
    else:
        mud, network = _endpoint_matches(key, model)
        if mud:
            matches["ietf-mud:mud"] = mud
        matches[key.family] = network
        if key.protocol in {6, 17} and key.remote_port is not None:
            transport_name = "tcp" if key.protocol == 6 else "udp"
            if key.port_role == "device":
                port_name = "source-port" if key.direction == "from-device" else "destination-port"
            else:
                port_name = "destination-port" if key.direction == "from-device" else "source-port"
            transport: dict[str, Any] = {port_name: {"operator": "eq", "port": key.remote_port}}
            if key.protocol == 6 and key.direction == "from-device":
                transport["ietf-mud:direction-initiated"] = "from-device"
            matches[transport_name] = transport
    return {"name": name, "matches": matches, "actions": {"forwarding": "accept"}}


def _keep_rule(key: RuleKey, stats: RuleStats, *, min_packets: int, min_window_support: float, total_windows: int) -> bool:
    if stats.packets >= min_packets and len(stats.windows) / max(total_windows, 1) >= min_window_support:
        return True
    if key.remote_port in CONTROL_PORTS or key.family == "ethernet":
        return True
    if key.remote_ip:
        try:
            address = ipaddress.ip_address(key.remote_ip)
            return address.is_multicast or str(address) == "255.255.255.255"
        except ValueError:
            pass
    return False


def generate_profile(
    model: CaptureModel,
    *,
    min_packets: int | None = 2,
    min_named_packets: int | None = None,
    min_window_support: float = 0.0,
    require_bidirectional_public_ip: bool = False,
) -> dict[str, Any]:
    """Convert a capture model to an RFC 8520-shaped MUD document."""

    device = _slug(model.device_name)
    effective_min_packets = (
        max(2, min(5000, math.ceil(model.packet_count * 0.01)))
        if min_packets is None
        else min_packets
    )
    total_windows = max(1, int((model.end_time - model.start_time) // WINDOW_SECONDS) + 1)
    retained = [
        (key, stats)
        for key, stats in model.rules.items()
        if _keep_rule(
            key,
            stats,
            min_packets=(
                min_named_packets
                if min_named_packets is not None and key.remote_ip in model.dns_by_ip
                else effective_min_packets
            ),
            min_window_support=min_window_support,
            total_windows=total_windows,
        )
    ]
    if require_bidirectional_public_ip:
        outbound = {key.remote_ip for key in model.rules if key.direction == "from-device"}
        inbound = {key.remote_ip for key in model.rules if key.direction == "to-device"}
        paired_ips = outbound & inbound
        def has_flow_evidence(key: RuleKey) -> bool:
            if not key.remote_ip or key.remote_ip in paired_ips or model.dns_by_ip.get(key.remote_ip):
                return True
            try:
                return not ipaddress.ip_address(key.remote_ip).is_global
            except ValueError:
                return True
        retained = [(key, stats) for key, stats in retained if has_flow_evidence(key)]
    # DHCP broadcast is both an observed broadcast endpoint and the device's
    # request to its gateway. Keep both semantic views as separate ACEs.
    retained.extend(
        (
            RuleKey(
                direction=key.direction,
                family=key.family,
                protocol=key.protocol,
                remote_ip=key.remote_ip,
                remote_port=key.remote_port,
                port_role="gateway",
                ethertype=key.ethertype,
            ),
            stats,
        )
        for key, stats in list(retained)
        if key.family in {"ipv4", "ipv6"}
        and key.direction == "from-device"
        and key.protocol == 17
        and key.remote_port in {67, 68}
    )
    # First generalize statistically broad port sets instead of memorizing
    # ephemeral ports. Control-plane ports are never generalized.
    port_groups: dict[tuple[str, str, str, str], list[tuple[RuleKey, RuleStats]]] = defaultdict(list)
    for key, stats in retained:
        mud, network = _endpoint_matches(key, model) if key.family != "ethernet" else ({}, {})
        endpoint_signature = json.dumps([mud, network], sort_keys=True)
        port_groups[(key.direction, key.family, str(key.protocol), endpoint_signature)].append((key, stats))

    generalized: list[tuple[RuleKey, RuleStats]] = []
    for rows in port_groups.values():
        distinct_ports = {key.remote_port for key, _ in rows if key.remote_port is not None}
        may_generalize = (
            len(distinct_ports) >= 12
            and not (distinct_ports & CONTROL_PORTS)
            and all(key.family != "ethernet" for key, _ in rows)
        )
        if not may_generalize:
            generalized.extend(rows)
            continue
        representative = rows[0][0]
        merged_stats = RuleStats()
        for _, stats in rows:
            merged_stats.merge(stats)
        generalized.append(
            (
                RuleKey(
                    direction=representative.direction,
                    family=representative.family,
                    protocol=representative.protocol,
                    remote_ip=representative.remote_ip,
                    remote_port=None,
                    port_role=representative.port_role,
                    ethertype=representative.ethertype,
                ),
                merged_stats,
            )
        )

    # Many cloud services rotate through several IP addresses. If DNS, protocol,
    # port, direction, and endpoint abstraction produce the same ACE, merge the
    # observations rather than emitting an ACE for every backing address.
    canonical: dict[tuple[str, str, str], tuple[RuleKey, RuleStats]] = {}
    for key, stats in generalized:
        match_signature = json.dumps(_ace(key, model, "")["matches"], sort_keys=True)
        signature = (key.direction, key.family, match_signature)
        if signature not in canonical:
            canonical[signature] = (key, RuleStats())
        canonical[signature][1].merge(stats)

    grouped: dict[tuple[str, str], list[tuple[RuleKey, RuleStats]]] = defaultdict(list)
    for key, stats in canonical.values():
        grouped[(key.direction, key.family)].append((key, stats))

    acl_documents: list[dict[str, Any]] = []
    from_lists: list[dict[str, str]] = []
    to_lists: list[dict[str, str]] = []
    statistics_rows: list[dict[str, Any]] = []
    family_order = {"ipv4": 0, "ipv6": 1, "ethernet": 2}
    for (direction, family), rows in sorted(grouped.items(), key=lambda item: (item[0][0], family_order.get(item[0][1], 9))):
        prefix = "from" if direction == "from-device" else "to"
        acl_name = f"{prefix}-{family}-{device}"
        aces = []
        def rule_sort_key(row: tuple[RuleKey, RuleStats]) -> tuple[str, str, str, str, int, str, str]:
            key = row[0]
            return (
                key.direction,
                key.family,
                str(key.protocol),
                key.remote_ip or "",
                key.remote_port if key.remote_port is not None else -1,
                key.port_role,
                key.ethertype or "",
            )

        for index, (key, stats) in enumerate(sorted(rows, key=rule_sort_key)):
            ace_name = f"{acl_name}-{index}"
            aces.append(_ace(key, model, ace_name))
            window_counts = [stats.windows.get(window, 0) for window in range(min(stats.windows), max(stats.windows) + 1)]
            statistics_rows.append(
                {
                    "ace": ace_name,
                    "packets": stats.packets,
                    "bytes": stats.bytes,
                    "window_support": round(len(stats.windows) / total_windows, 4),
                    "packets_per_5m": _robust_summary(window_counts),
                }
            )
        acl_type = "ethernet-acl-type" if family == "ethernet" else f"{family}-acl-type"
        acl_documents.append({"name": acl_name, "type": acl_type, "aces": {"ace": aces}})
        (from_lists if direction == "from-device" else to_lists).append({"name": acl_name})

    updated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    mud = {
        "mud-version": 1,
        "mud-url": f"urn:automud:generated:{device}",
        "last-update": updated,
        "cache-validity": 48,
        "is-supported": True,
        "systeminfo": model.device_name,
        "from-device-policy": {"access-lists": {"access-list": from_lists}},
        "to-device-policy": {"access-lists": {"access-list": to_lists}},
    }
    return {
        "ietf-mud:mud": mud,
        "ietf-access-control-list:access-lists": {"acl": acl_documents},
        "automud:behavioral-statistics": {
            "source-pcap": model.pcap.name,
            "device-mac": model.device_mac,
            "packets-observed": model.packet_count,
            "window-seconds": WINDOW_SECONDS,
            "total-windows": total_windows,
            "filter": {
                "min-packets": effective_min_packets,
                "min-packets-mode": "adaptive-1pct-capped-5000" if min_packets is None else "fixed",
                "min-named-packets": min_named_packets,
                "min-window-support": min_window_support,
                "require-bidirectional-public-ip": require_bidirectional_public_ip,
            },
            "rules": statistics_rows,
        },
    }


def write_profile(profile: dict[str, Any], output: str | Path) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return output_path


def _cached_model(pcap: Path, cache_directory: Path | None) -> CaptureModel:
    if cache_directory is None:
        return profile_pcap(pcap)

    cache_directory.mkdir(parents=True, exist_ok=True)
    cache_path = cache_directory / f"{pcap.name}.model.pkl"
    stat = pcap.stat()
    fingerprint = {
        "version": CACHE_VERSION,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }
    if cache_path.exists():
        try:
            with cache_path.open("rb") as handle:
                cached = pickle.load(handle)
            if cached.get("fingerprint") == fingerprint and isinstance(cached.get("model"), CaptureModel):
                print(f"Using cached observations for {pcap.name}", flush=True)
                return cached["model"]
        except (AttributeError, EOFError, OSError, pickle.PickleError, TypeError, ValueError):
            pass

    model = profile_pcap(pcap)
    temporary = cache_path.with_suffix(cache_path.suffix + ".tmp")
    with temporary.open("wb") as handle:
        pickle.dump({"fingerprint": fingerprint, "model": model}, handle, protocol=pickle.HIGHEST_PROTOCOL)
    temporary.replace(cache_path)
    return model


def generate_directory(
    pcap_directory: str | Path,
    output_directory: str | Path,
    *,
    min_packets: int | None = 2,
    min_named_packets: int | None = None,
    min_window_support: float = 0.0,
    require_bidirectional_public_ip: bool = False,
    cache_directory: str | Path | None = None,
) -> list[Path]:
    outputs = []
    pcaps = sorted(
        path
        for path in Path(pcap_directory).iterdir()
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}
    )
    for pcap in pcaps:
        print(f"Profiling {pcap.name} ...", flush=True)
        model = _cached_model(pcap, Path(cache_directory) if cache_directory is not None else None)
        profile = generate_profile(
            model,
            min_packets=min_packets,
            min_named_packets=min_named_packets,
            min_window_support=min_window_support,
            require_bidirectional_public_ip=require_bidirectional_public_ip,
        )
        output = write_profile(profile, Path(output_directory) / f"{pcap.stem}.mud.json")
        print(f"Wrote {output}", flush=True)
        outputs.append(output)
    if not outputs:
        raise FileNotFoundError(f"No .pcap or .pcapng files found in {pcap_directory}")
    return outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap_dir", type=Path, help="Directory containing one device capture per .pcap file")
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed/generated_muds"))
    parser.add_argument("--min-packets", type=int, default=2)
    parser.add_argument("--min-named-packets", type=int)
    parser.add_argument("--min-window-support", type=float, default=0.0)
    parser.add_argument("--require-bidirectional-public-ip", action="store_true")
    parser.add_argument("--cache-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    outputs = generate_directory(
        args.pcap_dir,
        args.output_dir,
        min_packets=args.min_packets,
        min_named_packets=args.min_named_packets,
        min_window_support=args.min_window_support,
        require_bidirectional_public_ip=args.require_bidirectional_public_ip,
        cache_directory=args.cache_dir,
    )
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

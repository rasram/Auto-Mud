"""Minimal streaming PCAP reader for MUD-relevant packet metadata.

This parser intentionally handles only Ethernet, VLAN, IPv4/IPv6, TCP, UDP,
ARP, and DNS. It is substantially faster than constructing complete Scapy
packet objects for multi-gigabyte captures. Unsupported link types should use
the Scapy fallback in generator.py.
"""

from __future__ import annotations

import ipaddress
import struct
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Any, BinaryIO, Iterator


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}


def _mac(raw: bytes) -> str:
    return ":".join(f"{value:02x}" for value in raw)


def _records(path: Path) -> Iterator[tuple[float, bytes]]:
    with path.open("rb", buffering=4 * 1024 * 1024) as handle:
        magic = handle.read(4)
        if magic == PCAPNG_MAGIC:
            handle.seek(0)
            yield from _pcapng_records(handle, path)
            return
        if magic not in PCAP_MAGICS:
            raise ValueError(f"Unsupported PCAP magic in {path.name}")
        endian, resolution = PCAP_MAGICS[magic]
        rest = handle.read(20)
        if len(rest) != 20:
            raise ValueError(f"Truncated PCAP header in {path.name}")
        link_type = struct.unpack(endian + "I", rest[16:20])[0]
        if link_type != 1:
            raise ValueError(f"Unsupported PCAP link type {link_type} in {path.name}")
        header = struct.Struct(endian + "IIII")
        while True:
            raw_header = handle.read(16)
            if not raw_header:
                return
            if len(raw_header) != 16:
                warnings.warn(f"Ignoring incomplete final packet header in {path.name}", RuntimeWarning)
                return
            seconds, fraction, captured_length, _ = header.unpack(raw_header)
            frame = handle.read(captured_length)
            if len(frame) != captured_length:
                warnings.warn(f"Ignoring incomplete final packet data in {path.name}", RuntimeWarning)
                return
            yield seconds + fraction / resolution, frame


def _options(body: bytes, offset: int, endian: str) -> Iterator[tuple[int, bytes]]:
    while offset + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[offset : offset + 4])
        offset += 4
        if code == 0:
            return
        if offset + length > len(body):
            return
        yield code, body[offset : offset + length]
        offset += (length + 3) & ~3


def _pcapng_records(handle: BinaryIO, path: Path) -> Iterator[tuple[float, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float, int]] = []
    while True:
        header = handle.read(8)
        if not header:
            return
        if len(header) != 8:
            warnings.warn(f"Ignoring incomplete final PCAPNG block header in {path.name}", RuntimeWarning)
            return
        raw_type, raw_length = header[:4], header[4:8]
        if raw_type == PCAPNG_MAGIC:
            byte_order = handle.read(4)
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError(f"Invalid PCAPNG byte-order magic in {path.name}")
            total_length = struct.unpack(endian + "I", raw_length)[0]
            remaining = handle.read(total_length - 12)
            if len(remaining) != total_length - 12:
                warnings.warn(f"Ignoring incomplete final PCAPNG section in {path.name}", RuntimeWarning)
                return
            interfaces = []
            continue

        block_type = struct.unpack(endian + "I", raw_type)[0]
        total_length = struct.unpack(endian + "I", raw_length)[0]
        if total_length < 12 or total_length % 4:
            raise ValueError(f"Invalid PCAPNG block length in {path.name}")
        remainder = handle.read(total_length - 8)
        if len(remainder) != total_length - 8:
            warnings.warn(f"Ignoring incomplete final PCAPNG block in {path.name}", RuntimeWarning)
            return
        if struct.unpack(endian + "I", remainder[-4:])[0] != total_length:
            raise ValueError(f"Mismatched PCAPNG block length in {path.name}")
        body = remainder[:-4]

        if block_type == 1 and len(body) >= 8:
            link_type = struct.unpack(endian + "H", body[:2])[0]
            resolution = 1e-6
            timestamp_offset = 0
            for code, value in _options(body, 8, endian):
                if code == 9 and value:
                    exponent = value[0]
                    resolution = 2.0 ** -(exponent & 0x7F) if exponent & 0x80 else 10.0 ** -exponent
                elif code == 14 and len(value) >= 8:
                    timestamp_offset = struct.unpack(endian + "q", value[:8])[0]
            interfaces.append((link_type, resolution, timestamp_offset))
        elif block_type == 6 and len(body) >= 20:
            interface_id, timestamp_high, timestamp_low, captured_length, _ = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if interface_id >= len(interfaces):
                continue
            link_type, resolution, timestamp_offset = interfaces[interface_id]
            if link_type != 1 or 20 + captured_length > len(body):
                continue
            timestamp = ((timestamp_high << 32) | timestamp_low) * resolution + timestamp_offset
            yield timestamp, body[20 : 20 + captured_length]
        elif block_type == 2 and len(body) >= 20:
            interface_id = struct.unpack(endian + "H", body[:2])[0]
            timestamp_high, timestamp_low, captured_length, _ = struct.unpack(endian + "IIII", body[4:20])
            if interface_id >= len(interfaces):
                continue
            link_type, resolution, timestamp_offset = interfaces[interface_id]
            if link_type != 1 or 20 + captured_length > len(body):
                continue
            timestamp = ((timestamp_high << 32) | timestamp_low) * resolution + timestamp_offset
            yield timestamp, body[20 : 20 + captured_length]


def _dns_name(message: bytes, offset: int, seen: set[int] | None = None) -> tuple[str, int]:
    labels: list[str] = []
    original_offset = offset
    jumped = False
    seen = set() if seen is None else seen
    while offset < len(message):
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer in seen:
                raise ValueError("DNS pointer loop")
            seen.add(pointer)
            suffix, _ = _dns_name(message, pointer, seen)
            if suffix:
                labels.append(suffix)
            offset += 2
            jumped = True
            break
        offset += 1
        if length > 63 or offset + length > len(message):
            raise ValueError("invalid DNS label")
        labels.append(message[offset : offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(label for label in labels if label).lower(), offset if jumped or offset != original_offset else original_offset


def _dns_addresses(payload: bytes, tcp: bool = False) -> tuple[set[str], list[tuple[str, str]]]:
    if tcp:
        if len(payload) < 2:
            return set(), []
        length = int.from_bytes(payload[:2], "big")
        payload = payload[2 : 2 + length]
    if len(payload) < 12:
        return set(), []
    try:
        qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHH", payload[4:12])
        offset = 12
        queries: set[str] = set()
        for _ in range(qd_count):
            name, offset = _dns_name(payload, offset)
            if offset + 4 > len(payload):
                return queries, []
            offset += 4
            if name:
                queries.add(name)
        addresses: list[tuple[str, str]] = []
        for _ in range(an_count + ns_count + ar_count):
            owner, offset = _dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            record_type, _, _, data_length = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10
            if offset + data_length > len(payload):
                break
            data = payload[offset : offset + data_length]
            offset += data_length
            if record_type == 1 and data_length == 4:
                addresses.append((str(ipaddress.ip_address(data)), owner))
            elif record_type == 28 and data_length == 16:
                addresses.append((str(ipaddress.ip_address(data)), owner))
        return queries, addresses
    except (ValueError, struct.error):
        return set(), []


def _transport(
    frame: bytes, offset: int, protocol: int
) -> tuple[int | None, int | None, bytes]:
    if protocol == 6 and offset + 20 <= len(frame):
        source, destination = struct.unpack("!HH", frame[offset : offset + 4])
        header_length = (frame[offset + 12] >> 4) * 4
        if header_length < 20:
            header_length = 20
        return source, destination, frame[offset + header_length :]
    if protocol == 17 and offset + 8 <= len(frame):
        source, destination = struct.unpack("!HH", frame[offset : offset + 4])
        return source, destination, frame[offset + 8 :]
    return None, None, b""


def profile_pcap_fast(
    path: Path,
    device_mac: str,
    device_name: str,
    rule_key_type: Any,
    rule_stats_type: Any,
    capture_model_type: Any,
    window_seconds: int,
) -> Any:
    dns_by_ip: dict[str, set[str]] = defaultdict(set)
    rules: dict[Any, Any] = defaultdict(rule_stats_type)
    device_bytes = bytes.fromhex(device_mac.replace(":", ""))
    start_time = float("inf")
    end_time = float("-inf")
    packet_count = 0

    for timestamp, frame in _records(path):
        if len(frame) < 14:
            continue
        destination_mac, source_mac = frame[:6], frame[6:12]
        if source_mac == device_bytes:
            direction = "from-device"
        elif destination_mac == device_bytes:
            direction = "to-device"
        else:
            continue
        packet_count += 1
        start_time = min(start_time, timestamp)
        end_time = max(end_time, timestamp)
        ethertype = int.from_bytes(frame[12:14], "big")
        offset = 14
        while ethertype in VLAN_TYPES and offset + 4 <= len(frame):
            ethertype = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4

        family = "ethernet"
        protocol: int | str = "arp" if ethertype == 0x0806 else 0
        remote_ip = None
        remote_port = None
        port_role = "remote"
        source_port = destination_port = None
        payload = b""

        if ethertype == 0x0800 and offset + 20 <= len(frame):
            header_length = (frame[offset] & 0x0F) * 4
            if header_length < 20 or offset + header_length > len(frame):
                continue
            family = "ipv4"
            protocol = frame[offset + 9]
            source_ip = str(ipaddress.ip_address(frame[offset + 12 : offset + 16]))
            destination_ip = str(ipaddress.ip_address(frame[offset + 16 : offset + 20]))
            remote_ip = destination_ip if direction == "from-device" else source_ip
            source_port, destination_port, payload = _transport(frame, offset + header_length, int(protocol))
        elif ethertype == 0x86DD and offset + 40 <= len(frame):
            family = "ipv6"
            protocol = frame[offset + 6]
            source_ip = str(ipaddress.ip_address(frame[offset + 8 : offset + 24]))
            destination_ip = str(ipaddress.ip_address(frame[offset + 24 : offset + 40]))
            remote_ip = destination_ip if direction == "from-device" else source_ip
            source_port, destination_port, payload = _transport(frame, offset + 40, int(protocol))

        if family != "ethernet" and protocol in {6, 17}:
            remote_port = destination_port if direction == "from-device" else source_port
            if protocol == 6 and remote_ip:
                address = ipaddress.ip_address(remote_ip)
                if address.is_private or address.is_link_local:
                    remote_port = source_port if direction == "from-device" else destination_port
                    port_role = "device"
            if source_port == 53 or destination_port == 53:
                queries, answers = _dns_addresses(payload, tcp=protocol == 6)
                for address, owner in answers:
                    if owner:
                        dns_by_ip[address].add(owner)
                    dns_by_ip[address].update(queries)

        key = rule_key_type(
            direction=direction,
            family=family,
            protocol=protocol,
            remote_ip=remote_ip,
            remote_port=remote_port,
            port_role=port_role,
            ethertype=f"0x{ethertype:04x}" if family == "ethernet" else None,
        )
        rules[key].observe(len(frame), int(timestamp // window_seconds))

    if not packet_count:
        raise ValueError(f"No Ethernet packets for {device_mac} found in {path}")
    return capture_model_type(
        pcap=path,
        device_name=device_name,
        device_mac=device_mac,
        dns_by_ip=dict(dns_by_ip),
        rules=dict(rules),
        start_time=start_time,
        end_time=end_time,
        packet_count=packet_count,
    )

#!/usr/bin/env python3
"""Animate packets from a PCAP over the IoT topology in topology.json.

The viewer uses Tkinter for the GUI and Scapy for packet decoding.  Known
device IPs are taken from topology.json.  Destinations outside the topology
are grouped behind a gateway node, while their real addresses remain visible
in the packet table.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError as exc:  # pragma: no cover - depends on system packages
    raise SystemExit("Tkinter is required. On Ubuntu: sudo apt install python3-tk") from exc

try:
    from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, PcapReader
except ImportError as exc:  # pragma: no cover - depends on system packages
    raise SystemExit("Scapy is required. On Ubuntu: sudo apt install python3-scapy") from exc


Point = Tuple[float, float]
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOPOLOGY = PROJECT_ROOT / "network" / "testbed" / "topology.json"


@dataclass(frozen=True)
class PacketEvent:
    number: int
    timestamp: float
    relative_time: float
    source: str
    destination: str
    protocol: str
    source_port: Optional[int]
    destination_port: Optional[int]
    length: int


@dataclass
class MovingPacket:
    event: PacketEvent
    path: List[Point]
    age: float = 0.0
    lifetime: float = 0.65
    canvas_item: Optional[int] = None


def short_device_name(device_key: str) -> str:
    return device_key.split("_", 1)[0]


def load_topology(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data.get("devices"), list) or not isinstance(data.get("device_ip"), dict):
        raise ValueError("topology.json must contain 'devices' and 'device_ip'")
    return data


def packet_endpoints(packet) -> Optional[Tuple[str, str]]:
    if IP in packet:
        return str(packet[IP].src), str(packet[IP].dst)
    if IPv6 in packet:
        return str(packet[IPv6].src), str(packet[IPv6].dst)
    if ARP in packet:
        return str(packet[ARP].psrc), str(packet[ARP].pdst)
    return None


def packet_protocol(packet) -> Tuple[str, Optional[int], Optional[int]]:
    if TCP in packet:
        return "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
    if UDP in packet:
        return "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
    if ICMP in packet:
        return "ICMP", None, None
    if ARP in packet:
        return "ARP", None, None
    if IPv6 in packet:
        return f"IPv6/{int(packet[IPv6].nh)}", None, None
    if IP in packet:
        return f"IP/{int(packet[IP].proto)}", None, None
    return "Other", None, None


def read_pcap(path: Path, known_ips: Iterable[str], max_packets: int = 0) -> Tuple[List[PacketEvent], int]:
    known = set(known_ips)
    events: List[PacketEvent] = []
    skipped = 0
    first_timestamp: Optional[float] = None

    with PcapReader(str(path)) as reader:
        for packet_number, packet in enumerate(reader, start=1):
            endpoints = packet_endpoints(packet)
            if endpoints is None:
                skipped += 1
                continue

            source, destination = endpoints

            # The capture may have been taken on Linux "any". Exclude unrelated
            # VM traffic while retaining packets to/from every topology device.
            if source not in known and destination not in known:
                skipped += 1
                continue

            timestamp = float(packet.time)
            if first_timestamp is None:
                first_timestamp = timestamp

            protocol, source_port, destination_port = packet_protocol(packet)
            events.append(
                PacketEvent(
                    number=packet_number,
                    timestamp=timestamp,
                    relative_time=timestamp - first_timestamp,
                    source=source,
                    destination=destination,
                    protocol=protocol,
                    source_port=source_port,
                    destination_port=destination_port,
                    length=len(packet),
                )
            )

            if max_packets and len(events) >= max_packets:
                break

            if packet_number % 100000 == 0:
                print(f"Decoded {packet_number:,} packets...", file=sys.stderr)

    return events, skipped


class PacketTopologyViewer:
    PROTOCOL_COLORS = {
        "TCP": "#3b82f6",
        "UDP": "#22c55e",
        "ICMP": "#f59e0b",
        "ARP": "#a855f7",
        "Other": "#94a3b8",
    }

    def __init__(self, root: tk.Tk, topology: dict, events: Sequence[PacketEvent], skipped: int, speed: float):
        self.root = root
        self.topology = topology
        self.events = events
        self.skipped = skipped
        self.index = 0
        self.virtual_time = 0.0
        self.last_tick = time.perf_counter()
        self.playing = False
        self.active_packets: List[MovingPacket] = []
        self.positions: Dict[str, Point] = {}
        self.node_counts: Counter[str] = Counter()
        self.node_count_items: Dict[str, int] = {}
        self.recent_events = deque(maxlen=250)

        self.device_to_ip = topology["device_ip"]
        self.ip_to_device = {ip: device for device, ip in self.device_to_ip.items()}
        self.device_names = {
            device: short_device_name(device) for device in topology["devices"]
        }

        self.root.title("Mininet PCAP Topology Viewer")
        self.root.geometry("1280x820")
        self.root.minsize(850, 600)

        self.speed_var = tk.StringVar(value=self._format_speed(speed))
        self.protocol_var = tk.StringVar(value="All")
        self.progress_var = tk.StringVar(value="Packet 0 / 0")
        self.time_var = tk.StringVar(value="t = 0.000 s")
        self.detail_var = tk.StringVar(value="Ready")

        self._build_ui()
        self._redraw_topology()
        self.root.after(16, self._tick)

    @staticmethod
    def _format_speed(speed: float) -> str:
        return f"{speed:g}x"

    def _current_speed(self) -> float:
        text = self.speed_var.get().strip().lower().removesuffix("x")
        try:
            return max(float(text), 0.01)
        except ValueError:
            self.speed_var.set("100x")
            return 100.0

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root, padding=(10, 8))
        toolbar.pack(fill=tk.X)

        self.play_button = ttk.Button(toolbar, text="Play", command=self.toggle_play)
        self.play_button.pack(side=tk.LEFT)

        ttk.Button(toolbar, text="Restart", command=self.restart).pack(side=tk.LEFT, padx=(6, 14))

        ttk.Label(toolbar, text="Speed").pack(side=tk.LEFT)
        speed_box = ttk.Combobox(
            toolbar,
            width=9,
            textvariable=self.speed_var,
            values=("1x", "10x", "100x", "1000x", "3600x", "10000x"),
        )
        speed_box.pack(side=tk.LEFT, padx=(5, 14))

        ttk.Label(toolbar, text="Protocol").pack(side=tk.LEFT)
        protocol_box = ttk.Combobox(
            toolbar,
            width=9,
            state="readonly",
            textvariable=self.protocol_var,
            values=("All", "TCP", "UDP", "ICMP", "ARP", "Other"),
        )
        protocol_box.pack(side=tk.LEFT, padx=(5, 14))

        ttk.Label(toolbar, textvariable=self.progress_var).pack(side=tk.LEFT, padx=(6, 14))
        ttk.Label(toolbar, textvariable=self.time_var).pack(side=tk.LEFT)

        self.canvas = tk.Canvas(self.root, background="#0f172a", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", lambda _event: self._redraw_topology())

        table_frame = ttk.Frame(self.root, padding=(8, 5, 8, 8))
        table_frame.pack(fill=tk.X)

        columns = ("number", "time", "source", "destination", "protocol", "ports", "bytes")
        self.packet_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=7)
        headings = {
            "number": "PCAP #",
            "time": "Time",
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "ports": "Ports",
            "bytes": "Bytes",
        }
        widths = {
            "number": 70,
            "time": 95,
            "source": 215,
            "destination": 215,
            "protocol": 85,
            "ports": 115,
            "bytes": 70,
        }
        for column in columns:
            self.packet_table.heading(column, text=headings[column])
            self.packet_table.column(column, width=widths[column], anchor=tk.W)
        self.packet_table.pack(fill=tk.X)

        ttk.Label(table_frame, textvariable=self.detail_var).pack(fill=tk.X, pady=(5, 0))

        self.root.bind("<space>", lambda _event: self.toggle_play())
        self.root.bind("<Home>", lambda _event: self.restart())

    def toggle_play(self) -> None:
        if self.index >= len(self.events):
            self.restart()
        self.playing = not self.playing
        self.play_button.configure(text="Pause" if self.playing else "Play")
        self.last_tick = time.perf_counter()

    def restart(self) -> None:
        self.index = 0
        self.virtual_time = 0.0
        self.active_packets.clear()
        self.node_counts.clear()
        self.recent_events.clear()
        self.packet_table.delete(*self.packet_table.get_children())
        self.progress_var.set(f"Packet 0 / {len(self.events):,}")
        self.time_var.set("t = 0.000 s")
        self.detail_var.set("Ready")
        self._redraw_topology()
        self.last_tick = time.perf_counter()

    def _event_matches_filter(self, event: PacketEvent) -> bool:
        selected = self.protocol_var.get()
        if selected == "All":
            return True
        if selected == "Other":
            return event.protocol not in {"TCP", "UDP", "ICMP", "ARP"}
        return event.protocol == selected

    def _endpoint_key(self, address: str) -> str:
        device = self.ip_to_device.get(address)
        return device if device is not None else "__gateway__"

    def _packet_path(self, event: PacketEvent) -> List[Point]:
        source_key = self._endpoint_key(event.source)
        destination_key = self._endpoint_key(event.destination)
        source = self.positions.get(source_key, self.positions["__gateway__"])
        destination = self.positions.get(destination_key, self.positions["__gateway__"])
        switch = self.positions["__switch__"]

        if source_key == destination_key:
            # A small loop makes external-to-external or same-node packets visible.
            return [source, (source[0], source[1] - 45), (source[0] + 35, source[1]), source]
        return [source, switch, destination]

    def _protocol_color(self, protocol: str) -> str:
        return self.PROTOCOL_COLORS.get(protocol, self.PROTOCOL_COLORS["Other"])

    def _emit_event(self, event: PacketEvent) -> None:
        if not self._event_matches_filter(event):
            return

        source_key = self._endpoint_key(event.source)
        destination_key = self._endpoint_key(event.destination)
        self.node_counts[source_key] += 1
        self.node_counts[destination_key] += 1
        self._update_node_count(source_key)
        self._update_node_count(destination_key)

        moving = MovingPacket(event=event, path=self._packet_path(event))
        color = self._protocol_color(event.protocol)
        x, y = moving.path[0]
        moving.canvas_item = self.canvas.create_oval(
            x - 5,
            y - 5,
            x + 5,
            y + 5,
            fill=color,
            outline="#f8fafc",
            width=1,
            tags="packet",
        )
        self.active_packets.append(moving)

        source_label = self.device_names.get(self.ip_to_device.get(event.source, ""), event.source)
        destination_label = self.device_names.get(self.ip_to_device.get(event.destination, ""), event.destination)
        ports = ""
        if event.source_port is not None or event.destination_port is not None:
            ports = f"{event.source_port or '-'} → {event.destination_port or '-'}"

        row = (
            event.number,
            f"{event.relative_time:.3f}s",
            source_label,
            destination_label,
            event.protocol,
            ports,
            event.length,
        )
        item = self.packet_table.insert("", 0, values=row)
        self.recent_events.append(item)
        children = self.packet_table.get_children()
        if len(children) > 100:
            self.packet_table.delete(*children[100:])

        self.detail_var.set(
            f"{source_label} ({event.source}) → {destination_label} ({event.destination})  "
            f"{event.protocol}  {event.length} bytes"
        )

    @staticmethod
    def _point_on_path(path: Sequence[Point], progress: float) -> Point:
        if len(path) == 1:
            return path[0]

        lengths = [
            math.dist(path[index], path[index + 1])
            for index in range(len(path) - 1)
        ]
        total = sum(lengths)
        if total <= 0:
            return path[-1]

        target = min(max(progress, 0.0), 1.0) * total
        traversed = 0.0
        for index, segment_length in enumerate(lengths):
            if target <= traversed + segment_length or index == len(lengths) - 1:
                fraction = 0.0 if segment_length == 0 else (target - traversed) / segment_length
                x1, y1 = path[index]
                x2, y2 = path[index + 1]
                return x1 + (x2 - x1) * fraction, y1 + (y2 - y1) * fraction
            traversed += segment_length
        return path[-1]

    def _tick(self) -> None:
        now = time.perf_counter()
        real_delta = min(now - self.last_tick, 0.25)
        self.last_tick = now

        if self.playing and self.events:
            self.virtual_time += real_delta * self._current_speed()

            emitted = 0
            while self.index < len(self.events):
                event = self.events[self.index]
                if event.relative_time > self.virtual_time or emitted >= 2000:
                    break
                self._emit_event(event)
                self.index += 1
                emitted += 1

            if self.index >= len(self.events):
                self.playing = False
                self.play_button.configure(text="Play")
                self.detail_var.set(
                    f"Replay complete: {len(self.events):,} packets visualized; "
                    f"{self.skipped:,} unrelated or unsupported packets ignored"
                )

        surviving: List[MovingPacket] = []
        for moving in self.active_packets:
            if self.playing:
                moving.age += real_delta
            progress = moving.age / moving.lifetime
            if progress >= 1.0:
                if moving.canvas_item is not None:
                    self.canvas.delete(moving.canvas_item)
                continue
            if moving.canvas_item is not None:
                x, y = self._point_on_path(moving.path, progress)
                self.canvas.coords(moving.canvas_item, x - 5, y - 5, x + 5, y + 5)
            surviving.append(moving)
        self.active_packets = surviving

        total = len(self.events)
        self.progress_var.set(f"Packet {self.index:,} / {total:,}")
        self.time_var.set(f"t = {self.virtual_time:,.3f} s")
        self.root.after(16, self._tick)

    def _redraw_topology(self) -> None:
        width = max(self.canvas.winfo_width(), 850)
        height = max(self.canvas.winfo_height(), 400)
        self.canvas.delete("all")
        self.node_count_items.clear()

        center_x = width * 0.42
        center_y = height * 0.50
        radius_x = max(width * 0.31, 255)
        radius_y = max(height * 0.38, 145)

        devices = self.topology["devices"]
        self.positions = {"__switch__": (center_x, center_y)}
        for index, device in enumerate(devices):
            angle = -math.pi / 2 + (2 * math.pi * index / len(devices))
            self.positions[device] = (
                center_x + radius_x * math.cos(angle),
                center_y + radius_y * math.sin(angle),
            )
        self.positions["__gateway__"] = (width * 0.91, center_y)

        # Physical star topology.
        for device in devices:
            self.canvas.create_line(
                *self.positions[device],
                *self.positions["__switch__"],
                fill="#334155",
                width=2,
            )
        self.canvas.create_line(
            *self.positions["__switch__"],
            *self.positions["__gateway__"],
            fill="#64748b",
            width=3,
        )

        # Authored logical household edges from topology.json.
        for edge in self.topology.get("edges", []):
            source = self.positions.get(edge.get("source"))
            destination = self.positions.get(edge.get("dest"))
            if source and destination:
                self.canvas.create_line(
                    *source,
                    *destination,
                    fill="#f59e0b",
                    width=1,
                    dash=(5, 5),
                    arrow=tk.LAST,
                )

        self._draw_node("__switch__", "OVS switch", "s1", "#475569", radius=31)
        self._draw_node("__gateway__", "Gateway / Internet", "external IPs", "#7c3aed", radius=39)

        for device in devices:
            self._draw_node(
                device,
                self.device_names[device],
                self.device_to_ip[device],
                "#0f766e",
                radius=32,
            )

        legend_y = height - 18
        legend_x = 15
        for protocol in ("TCP", "UDP", "ICMP", "ARP", "Other"):
            color = self._protocol_color(protocol)
            self.canvas.create_oval(legend_x, legend_y - 5, legend_x + 10, legend_y + 5, fill=color, outline="")
            self.canvas.create_text(
                legend_x + 15,
                legend_y,
                text=protocol,
                fill="#cbd5e1",
                anchor=tk.W,
                font=("TkDefaultFont", 9),
            )
            legend_x += 78

        # Restore moving packet dots after a resize redraw.
        for moving in self.active_packets:
            moving.path = self._packet_path(moving.event)
            x, y = self._point_on_path(moving.path, moving.age / moving.lifetime)
            moving.canvas_item = self.canvas.create_oval(
                x - 5,
                y - 5,
                x + 5,
                y + 5,
                fill=self._protocol_color(moving.event.protocol),
                outline="#f8fafc",
                width=1,
                tags="packet",
            )

    def _draw_node(self, key: str, title: str, subtitle: str, color: str, radius: int) -> None:
        x, y = self.positions[key]
        self.canvas.create_oval(
            x - radius,
            y - radius,
            x + radius,
            y + radius,
            fill=color,
            outline="#cbd5e1",
            width=2,
        )
        self.canvas.create_text(
            x,
            y - 3,
            text=title,
            fill="#f8fafc",
            width=145,
            justify=tk.CENTER,
            font=("TkDefaultFont", 9, "bold"),
        )
        self.canvas.create_text(
            x,
            y + radius + 13,
            text=subtitle,
            fill="#cbd5e1",
            font=("TkDefaultFont", 8),
        )
        count_item = self.canvas.create_text(
            x,
            y + radius + 28,
            text=f"packets: {self.node_counts[key]:,}",
            fill="#94a3b8",
            font=("TkDefaultFont", 8),
        )
        self.node_count_items[key] = count_item

    def _update_node_count(self, key: str) -> None:
        item = self.node_count_items.get(key)
        if item is not None:
            self.canvas.itemconfigure(item, text=f"packets: {self.node_counts[key]:,}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Animate topology traffic from a PCAP capture."
    )
    parser.add_argument("pcap", type=Path, help="PCAP or PCAPNG file to visualize")
    parser.add_argument(
        "--topology",
        type=Path,
        default=DEFAULT_TOPOLOGY,
        help="Topology JSON file (default: network/testbed/topology.json)",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=100.0,
        help="Initial playback speed multiplier (default: 100)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Decode at most this many matching packets; 0 loads all packets",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    if not args.pcap.is_file():
        raise SystemExit(f"PCAP file not found: {args.pcap}")
    if not args.topology.is_file():
        raise SystemExit(f"Topology file not found: {args.topology}")

    topology = load_topology(args.topology)
    print(f"Reading {args.pcap}...", file=sys.stderr)
    events, skipped = read_pcap(
        args.pcap,
        topology["device_ip"].values(),
        max_packets=max(args.max_packets, 0),
    )
    print(
        f"Loaded {len(events):,} topology packets; skipped {skipped:,} unrelated/unsupported packets.",
        file=sys.stderr,
    )

    if not events:
        raise SystemExit("No packets involving topology device IPs were found in the capture.")

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit(
            "Could not open a graphical display. Run from the VM desktop or connect with SSH X11 forwarding (ssh -X)."
        ) from exc

    PacketTopologyViewer(root, topology, events, skipped, args.speed)
    root.mainloop()


if __name__ == "__main__":
    main()

"""Render a collection plan into a packet trace on a fast virtual clock.

This is a discrete packet simulator, not a Mininet socket run. Its capture keeps
the planned UTC timeline so the ordinary Zeek policy sees genuine 60-second
windows even though generation takes less wall time.
"""
import argparse
import heapq
from itertools import count
from pathlib import Path

from ml.schema import VERSION, file_hash, read_json, require, write_json, write_jsonl
from network.testbed.collection_plan import build_plan, inventory, label_intervals


def event_packets(event, ordinal, start, macs):
    from scapy.all import Ether, IP, TCP, UDP, Raw

    source_ip = macs[event["device_id"]][0]
    destination_ip = event["destination"]
    require(destination_ip in {ip for ip, _ in macs.values()},
            "Virtual capture destination is outside the local testbed")
    source_mac = macs[event["device_id"]][1]
    destination_mac = next((mac for ip, mac in macs.values() if ip == destination_ip), "02:00:00:00:01:00")
    base, duration = start + event["offset"], max(0.01, float(event["duration"]))
    sport, port = 40000 + ordinal % 20000, int(event["port"])
    request, response = int(event["request_bytes"]), int(event["response_bytes"])
    require(0 <= request <= 65536 and 0 <= response <= 65536 and 0 < port <= 65535, "Invalid virtual event")

    def frame(reverse, layer, payload=b""):
        src, dst = (destination_ip, source_ip) if reverse else (source_ip, destination_ip)
        smac, dmac = (destination_mac, source_mac) if reverse else (source_mac, destination_mac)
        return Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / layer / Raw(payload)

    def chunks(total):
        return [min(1400, total - i) for i in range(0, total, 1400)]

    packets = []
    if event["proto"] == "tcp":
        orig_seq, resp_seq = (10000 + ordinal * 70000) % (2 ** 32), (20000 + ordinal * 70000) % (2 ** 32)
        packets.append((base, frame(False, TCP(sport=sport, dport=port, flags="S", seq=orig_seq))))
        if event.get("expect_failure"):
            packets.append((base + min(0.02, duration / 2), frame(True,
                TCP(sport=port, dport=sport, flags="RA", seq=0, ack=(orig_seq + 1) % (2 ** 32)))))
            return packets
        packets.append((base + duration * .1, frame(True,
            TCP(sport=port, dport=sport, flags="SA", seq=resp_seq, ack=(orig_seq + 1) % (2 ** 32)))))
        orig_seq, resp_seq = (orig_seq + 1) % (2 ** 32), (resp_seq + 1) % (2 ** 32)
        packets.append((base + duration * .15, frame(False,
            TCP(sport=sport, dport=port, flags="A", seq=orig_seq, ack=resp_seq))))
        request_parts = chunks(request)
        for i, size in enumerate(request_parts):
            at = base + duration * (.2 + .3 * (i + 1) / (len(request_parts) + 1))
            packets.append((at, frame(False, TCP(sport=sport, dport=port, flags="PA", seq=orig_seq,
                ack=resp_seq), b"N" * size)))
            orig_seq = (orig_seq + size) % (2 ** 32)
        response_parts = chunks(response)
        for i, size in enumerate(response_parts):
            at = base + duration * (.55 + .3 * (i + 1) / (len(response_parts) + 1))
            packets.append((at, frame(True, TCP(sport=port, dport=sport, flags="PA", seq=resp_seq,
                ack=orig_seq), b"R" * size)))
            resp_seq = (resp_seq + size) % (2 ** 32)
        packets.append((base + duration * .95, frame(False,
            TCP(sport=sport, dport=port, flags="FA", seq=orig_seq, ack=resp_seq))))
        packets.append((base + duration, frame(True,
            TCP(sport=port, dport=sport, flags="FA", seq=resp_seq, ack=(orig_seq + 1) % (2 ** 32)))))
    elif event["proto"] == "udp":
        requests, responses = chunks(request), chunks(response)
        for i in range(max(len(requests), len(responses), 1)):
            at = base + duration * i / max(len(requests), len(responses), 1)
            if i < len(requests):
                packets.append((at, frame(False, UDP(sport=sport, dport=port), b"N" * requests[i])))
            if i < len(responses):
                packets.append((at + duration / max(len(requests), len(responses), 1) * .5,
                                frame(True, UDP(sport=port, dport=sport), b"R" * responses[i])))
    else:
        raise ValueError("Virtual capture supports TCP/UDP plans only")
    return packets


def render(plan_path, out, start, smoke=False):
    from scapy.utils import PcapWriter

    plan_path, out = Path(plan_path).resolve(), Path(out).resolve()
    plan = read_json(plan_path)
    require(plan.get("schema_version") == "automud.collection.v1", "Unknown collection plan")
    require(isinstance(start, int) and start % 60 == 0, "Virtual start must be a UTC minute boundary")
    require(plan["calibrated"] or smoke, "Uncalibrated virtual capture is smoke data")
    profiles = None
    if plan.get("profiles_file"):
        require(file_hash(plan["profiles_file"]) == plan["profiles_sha256"], "Calibration profile changed")
        profiles = read_json(plan["profiles_file"])
    require(not out.exists(), "Use a new virtual capture directory")
    out.mkdir(parents=True)
    topology = plan["topology"]
    if plan.get("utc_phase", 0) != start % 86400:
        plan = {**plan, **build_plan(topology, plan["duration"], plan["seed"], profiles,
            plan["scenario"], plan["actor"], plan["onset"], plan["normal_control"], start % 86400)}
        write_json(out / "executed-plan.json", plan)
        executed_hash = file_hash(out / "executed-plan.json")
    else:
        executed_hash = file_hash(plan_path)
    macs = {d["device_id"]: (d["addresses"][0]["ip"], d["mac"])
            for d in inventory(topology, start, start + plan["duration"])}
    macs.update({f"cloud-{i}": (ip, "02:00:00:00:01:00") for i, ip in enumerate(plan["cloud_ips"])})
    queue, serial = [], count()
    packet_count = 0
    writer = PcapWriter(str(out / "capture.pcap"), linktype=1, sync=False)
    try:
        for ordinal, event in enumerate(plan["events"]):
            deadline = start + event["offset"]
            while queue and queue[0][0] <= deadline:
                ts, _, packet = heapq.heappop(queue)
                packet.time = ts
                writer.write(packet)
                packet_count += 1
            for ts, packet in event_packets(event, ordinal, start, macs):
                heapq.heappush(queue, (ts, next(serial), packet))
        while queue:
            ts, _, packet = heapq.heappop(queue)
            packet.time = ts
            writer.write(packet)
            packet_count += 1
    finally:
        writer.close()
    manifest = {"schema_version": VERSION, "run_id": plan["run_id"], "session_id": plan["session_id"],
        "source": "virtual_testbed", "start": start, "end": start + plan["duration"],
        "normal": not plan["scenario"] or plan["normal_control"], "capture_complete": True,
        "replay_speed": 1, "clock_mode": "virtual_packet_time", "synthetic": True,
        "capture_drops": 0, "calibrated_generator": plan["calibrated"], "smoke": smoke,
        "inventory": inventory(topology, start, start + plan["duration"]),
        "plan_sha256": file_hash(plan_path), "pcap_sha256": file_hash(out / "capture.pcap"),
        "executed_plan_sha256": executed_hash,
        "generated_packets": packet_count,
        "limitations": ["No Linux TCP retransmission/congestion/application stack", "Packet payload and transport timing are synthetic"]}
    write_json(out / "manifest.json", manifest)
    write_jsonl(out / "labels.jsonl", label_intervals(plan, start))
    return {"run": plan["run_id"], "packets": packet_count, "virtual_seconds": plan["duration"],
            "capture": str(out / "capture.pcap")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--start", type=int, required=True, help="UTC Unix seconds aligned to a minute")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    print(render(args.plan, args.out, args.start, args.smoke))


if __name__ == "__main__":
    main()

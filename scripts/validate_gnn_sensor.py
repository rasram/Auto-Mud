"""Executable packet-level acceptance check for the canonical Zeek policy.

Needs Scapy to generate the fixture, and Zeek to extract it. Generation and
checking can run on different hosts using --generate-only / --existing-fixture.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.schema import read_json, read_jsonl, write_json, validate_telemetry
from ml.dataset_prep.extract import extract


def generate(out):
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
    out.mkdir(parents=True, exist_ok=True)
    def tcp(reverse=False, flags="A", port=8080, seq=100, ack=0, payload=0):
        a, b = ("10.0.0.12", "10.0.0.11") if reverse else ("10.0.0.11", "10.0.0.12")
        ma, mb = ("02:00:00:00:00:02", "02:00:00:00:00:01") if reverse else ("02:00:00:00:00:01", "02:00:00:00:00:02")
        return Ether(src=ma, dst=mb) / IP(src=a, dst=b) / TCP(sport=port if reverse else 45000,
            dport=45000 if reverse else port, flags=flags, seq=seq, ack=ack) / Raw(b"X" * payload)
    packets = [(121, tcp(flags="S")), (121.1, tcp(True, "SA", seq=1000, ack=101)),
               (121.2, tcp(seq=101, ack=1001)), (130, tcp(flags="PA", seq=101, ack=1001, payload=20)),
               (170, tcp(flags="S", port=9999, seq=1)),
               (185, tcp(flags="PA", seq=121, ack=1001, payload=20)),
               (186, tcp(True, "PA", seq=1001, ack=141, payload=20)),
               (247, Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                IPv6(src="fd00::11", dst="fd00::12") / UDP(sport=45001, dport=5353) / Raw(b"X" * 20))]
    totals = {}
    for ts, packet in packets:
        packet.time = ts
        row = totals.setdefault(str(int(ts // 60) * 60), {"packets": 0, "ip_bytes": 0})
        row["packets"] += 1
        row["ip_bytes"] += len(bytes(packet[IP] if IP in packet else packet[IPv6]))
    wrpcap(str(out / "fixture.pcap"), [p for _, p in packets])
    write_json(out / "expected.json", totals)


def check(out):
    rows = [validate_telemetry(r) for r in read_jsonl(out / "zeek" / "telemetry.jsonl")]
    totals = {}
    for r in rows:
        count = totals.setdefault(str(int(r["window_start"])), {"packets": 0, "ip_bytes": 0})
        count["packets"] += r["orig_pkts"] + r["resp_pkts"]
        count["ip_bytes"] += r["orig_ip_bytes"] + r["resp_ip_bytes"]
    assert totals == read_json(out / "expected.json"), (totals, read_json(out / "expected.json"))
    stream = sorted([r for r in rows if r.get("resp_p") == 8080], key=lambda r: r["window_start"])
    assert len(stream) == 2 and stream[0]["uid"] == stream[1]["uid"]
    assert [r["new_flow"] for r in stream] == [True, False]
    assert all(r["established"] and not r["failed"] for r in stream)
    assert next(r for r in rows if r.get("resp_p") == 9999)["failed"]
    assert next(r for r in rows if r["orig_h"] == "fd00::11")["orig_ip_bytes"] == 68
    print("Sensor acceptance passed: exact IPv4/IPv6 counters, interval deltas, handshake and failed SYN.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--zeek", default="zeek")
    p.add_argument("--generate-only", action="store_true")
    p.add_argument("--existing-fixture", action="store_true")
    p.add_argument("--check-only", action="store_true")
    a = p.parse_args()
    if not a.existing_fixture and not a.check_only:
        generate(a.out)
    if a.generate_only:
        return
    if not a.check_only:
        extract([a.out / "fixture.pcap"], a.out / "zeek", zeek=a.zeek)
    check(a.out)


if __name__ == "__main__":
    main()

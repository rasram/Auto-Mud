import asyncio
from pathlib import Path

from ml.schema import read_json, validate_labels
from network.testbed.collection_plan import build_plan, label_intervals, inventory
from network.testbed.socket_traffic import tcp_server, HEADER

TOPOLOGY = Path(__file__).resolve().parents[2] / "network" / "testbed" / "topology.json"


def test_seed_repeatability_and_global_timeline():
    topology = read_json(TOPOLOGY)
    p = build_plan(topology, 600, seed=3)
    assert p == build_plan(topology, 600, seed=3)
    assert p["events"] != build_plan(topology, 600, seed=4)["events"]
    assert [e["offset"] for e in p["events"]] == sorted(e["offset"] for e in p["events"])
    assert all(e["destination"].startswith("10.0.0.") for e in p["events"])
    assert not p["calibrated"]


def test_compromised_from_first_event_and_control():
    topology = read_json(TOPOLOGY)
    actor = topology["devices"][0]
    plan = build_plan(topology, 600, 3, scenario="port_scan", actor=actor)
    first = next(e for e in plan["events"] if e["device_id"] == actor)
    assert first["offset"] == 0 and first["kind"] == "port_scan"
    labels = label_intervals(plan, 120)
    positive = [r for r in labels if r["label"] == 1]
    assert len(positive) == 1 and positive[0]["device_id"] == actor
    assert positive[0]["start"] == 120
    control = build_plan(topology, 600, 3, scenario="port_scan", actor=actor, normal_control=True)
    assert plan["session_id"] == control["session_id"]  # paired runs must share a split
    assert not any(l["label"] for l in label_intervals(control, 120))


def test_later_onset_labels():
    topology = read_json(TOPOLOGY)
    actor = topology["devices"][0]
    plan = build_plan(topology, 600, 3, scenario="beaconing", actor=actor, onset="later")
    actor_labels = [r for r in label_intervals(plan, 120) if r["device_id"] == actor]
    assert [(r["start"], r["end"], r["label"]) for r in actor_labels] == [(120, 420, 0), (420, 720, 1)]


def test_real_tcp_request_response():
    async def exercise():
        server = await asyncio.start_server(tcp_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(HEADER.pack(100, 333) + b"N" * 100)
            await writer.drain()
            assert await reader.readexactly(333) == b"R" * 333
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(exercise())

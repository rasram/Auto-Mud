"""Small bidirectional lab transport. Only the Mininet runner starts these agents."""
import argparse
import asyncio
import ipaddress
import json
import socket
import struct
import time
from pathlib import Path

HEADER = struct.Struct("!II")
MAX_BYTES = 65536


async def tcp_server(reader, writer):
    try:
        while True:
            # Measured persistent streams may be idle between minute intervals.
            raw = await asyncio.wait_for(reader.readexactly(HEADER.size), 3700)
            request, response = HEADER.unpack(raw)
            if request > MAX_BYTES or response > MAX_BYTES: return
            await asyncio.wait_for(reader.readexactly(request), 65)
            writer.write(b"R" * response)
            await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


class UDPResponder(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) >= 4:
            wanted = min(struct.unpack("!I", data[:4])[0], 1400)
            if wanted:
                self.transport.sendto(b"R" * wanted, addr)


async def serve(plan,bind_ips=None):
    endpoints = set(tuple(e) for e in plan.get("service_endpoints", []))
    endpoints.update((e["proto"], int(e["port"])) for e in plan["events"] if not e.get("expect_failure"))
    if 'service_bindings' in plan:
        endpoints={(proto,port,ip) for ip,proto,port in plan['service_bindings'] if bind_ips is None or ip in bind_ips}
    else: endpoints={(proto,port,'0.0.0.0') for proto,port in endpoints}
    servers, transports = [], []
    loop = asyncio.get_running_loop()
    for proto, port,ip in endpoints:
        if proto == "tcp":
            servers.append(await asyncio.start_server(tcp_server, ip, port))
        elif proto == "udp":
            transport, _ = await loop.create_datagram_endpoint(UDPResponder, local_addr=(ip, port))
            transports.append(transport)
    print(json.dumps({"ready": True, "services": len(endpoints)}), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()
        for transport in transports:
            transport.close()


async def exchange(event):
    addr = ipaddress.ip_address(event["destination"])
    if addr not in ipaddress.ip_network("10.0.0.0/24"):
        raise ValueError("Collection transport only permits the isolated testbed subnet")
    request, response = event["request_bytes"], event["response_bytes"]
    if not (0 <= request <= MAX_BYTES and 0 <= response <= MAX_BYTES):
        raise ValueError("Traffic size exceeds collection bounds")
    if event["proto"] == "tcp":
        options={'local_addr':(event['source_ip'],0)} if event.get('source_ip') else {}
        reader, writer = await asyncio.wait_for(asyncio.open_connection(str(addr), event["port"],**options), 2)
        try:
            origin=time.monotonic()
            segments=event.get('segments',[dict(offset=0,request_bytes=request,response_bytes=response,duration=event['duration'])])
            for segment in segments:
                await asyncio.sleep(max(0,origin+segment['offset']-time.monotonic()))
                request,response=segment['request_bytes'],segment['response_bytes']
                if not(0<=request<=MAX_BYTES and 0<=response<=MAX_BYTES): raise ValueError('Invalid stream segment')
                writer.write(HEADER.pack(request,response))
                parts=max(1,min(20,request//128));left=request
                for i in range(parts):
                    n=left//(parts-i);writer.write(b'N'*n);await writer.drain();left-=n
                    await asyncio.sleep(segment['duration']/parts)
                if response: await asyncio.wait_for(reader.readexactly(response),15)
        finally:
            writer.close()
            await writer.wait_closed()
    elif event["proto"] == "udp":
        # One socket preserves the source port across a measured UDP stream.
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.setblocking(False)
        if event.get('source_ip'):sock.bind((event['source_ip'],0))
        loop=asyncio.get_running_loop();origin=time.monotonic()
        try:
            segments=event.get('segments',[dict(offset=0,request_bytes=request,response_bytes=response,duration=event['duration'])])
            for segment in segments:
                await asyncio.sleep(max(0,origin+segment['offset']-time.monotonic()))
                tx_left,rx_left=segment['request_bytes'],segment['response_bytes']
                if not(0<=tx_left<=MAX_BYTES and 0<=rx_left<=MAX_BYTES):raise ValueError('Invalid UDP stream segment')
                parts=max(1,(max(tx_left,rx_left)+1399)//1400)
                for i in range(parts):
                    tx,rx=min(1400,tx_left),min(1400,rx_left)
                    await loop.sock_sendto(sock,struct.pack('!I',rx)+b'N'*tx,(str(addr),event['port']))
                    if rx:
                        reply=await asyncio.wait_for(loop.sock_recv(sock,2048),2)
                        if len(reply)!=rx:raise ValueError('UDP response length mismatch')
                    tx_left-=tx;rx_left-=rx
                    await asyncio.sleep(segment['duration']/parts)
        finally:sock.close()
    else:
        raise ValueError("The normal collection transport supports TCP and UDP")


async def replay(plan, device, start):
    events = [e for e in plan["events"] if e["device_id"] == device or device=='cloud' and e['device_id'].startswith('cloud-')]
    sem = asyncio.Semaphore(plan["limits"]["max_concurrent_per_device"])
    debug = plan.get('debug_events',False)
    plan.clear()  # Each replay process retains only its own events.
    origin = time.monotonic() + (start - time.time())
    results = {"events": 0, "successful": 0, "expected_failures": 0, "unexpected_failures": 0, "late_events": 0}
    async def run_event(e):
        async with sem:
            lag = time.monotonic() - (origin + e["offset"])
            results["late_events"] += lag > 1
            results["events"] += 1
            if debug:
                print(json.dumps({'event':'start','offset':e['offset'],'proto':e['proto'],'port':e['port']}),flush=True)
            try:
                await exchange(e)
                results["successful"] += 1
                if e.get("expect_failure"):
                    results["unexpected_failures"] += 1
            except (OSError, asyncio.TimeoutError, ValueError, asyncio.IncompleteReadError) as exc:
                results["expected_failures" if e.get("expect_failure") else "unexpected_failures"] += 1
                print(json.dumps({"offset": e["offset"], "kind": e["kind"],
                    "proto":e["proto"],"port":e["port"],"request_bytes":e["request_bytes"],
                    "response_bytes":e["response_bytes"],"error_type":type(exc).__name__,"error":str(exc)}), flush=True)
            finally:
                if debug:
                    print(json.dumps({'event':'finish','offset':e['offset']}),flush=True)
    pending = set()
    for event in events:
        await asyncio.sleep(max(0, origin + event["offset"] - time.monotonic()))
        task = asyncio.create_task(run_event(event))
        pending.add(task)
        task.add_done_callback(pending.discard)
        # Bound queued work, too; the lag counter reveals an overloaded collection.
        if len(pending) >= 64:
            await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
    if pending:
        await asyncio.gather(*pending)
    print(json.dumps({"summary": results}), flush=True)
    return 1 if results["unexpected_failures"] or results["late_events"] else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("serve", "replay"))
    parser.add_argument("--plan", required=True)
    parser.add_argument("--device")
    parser.add_argument("--start", type=float)
    parser.add_argument("--bind-ips",nargs="+")
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text())
    if args.mode == "serve":
        if 'service_bindings' in plan:
            plan={'service_bindings':plan['service_bindings'],'events':[]}
        elif "service_endpoints" in plan:
            plan = {"service_endpoints": plan["service_endpoints"], "events": []}
        asyncio.run(serve(plan,args.bind_ips))
    else:
        if args.device is None or args.start is None:
            parser.error("replay needs --device and --start")
        raise SystemExit(asyncio.run(replay(plan, args.device, args.start)))


if __name__ == "__main__":
    main()

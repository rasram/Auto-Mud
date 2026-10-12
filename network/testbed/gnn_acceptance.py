"""Bounded ML handoff capture on its own isolated Mininet bridge; no Ryu/NAT."""
import argparse
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import json


def capture(out):
    if os.geteuid() != 0:
        raise RuntimeError('Run this network-only helper as root on a Linux lab host')
    try:
        from mininet.net import Mininet
    except ModuleNotFoundError:
        sys.path.append('/usr/lib/python3/dist-packages')
        from mininet.net import Mininet
    from mininet.node import OVSBridge
    bridge = 'amgnn0'
    if subprocess.run(['ovs-vsctl', 'br-exists', bridge], capture_output=True).returncode == 0:
        raise RuntimeError('Dedicated amgnn0 bridge already exists; do not overwrite it')
    root = Path(out).resolve()
    if root.exists():
        raise RuntimeError('Use a new capture directory')
    root.mkdir(parents=True)
    net = Mininet(controller=None, switch=OVSBridge, build=False, ipBase='10.123.0.0/24')
    switch = net.addSwitch(bridge, failMode='standalone')
    hosts = [net.addHost(name, ip=f'10.123.0.{i}/24') for i, name in enumerate(('amga', 'amgb', 'amgc'), 11)]
    for host in hosts:
        net.addLink(host, switch)
    sensor = net.addHost('amgsensor', ip=None)
    link = net.addLink(sensor, switch)
    processes = []
    handles = []
    recorder = None
    try:
        net.build(); net.start()
        for host in [*hosts, sensor]:
            (root / (host.name + '-offload.log')).write_text(host.cmd(f'ethtool -K {host.defaultIntf()} tx off rx off tso off gso off gro off 2>&1'))
        subprocess.run(['ovs-vsctl', '--', '--id=@p', 'get', 'Port', link.intf2.name,
                        '--', '--id=@m', 'create', 'Mirror', 'name=amgnn-observer', 'select-all=true', 'output-port=@p',
                        '--', 'set', 'Bridge', bridge, 'mirrors=@m'], check=True, capture_output=True)
        server_code = '''import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.123.0.12',5000));s.listen()
print('ready',flush=True)
while True:
 c,a=s.accept()
 with c:
  data=c.recv(4096)
  if data:c.sendall(b'R'*128)
'''
        handle = (root / 'responder.log').open('w'); handles.append(handle)
        responder = hosts[1].popen(['/usr/bin/python3', '-u', '-c', server_code], stdout=handle, stderr=subprocess.STDOUT)
        processes.append(responder)
        deadline = time.monotonic() + 10
        while 'ready' not in (root / 'responder.log').read_text():
            if responder.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('Responder did not start')
            time.sleep(.05)
        handle = (root / 'tcpdump.log').open('w'); handles.append(handle)
        recorder = sensor.popen(['tcpdump', '-U', '-n', '-s', '0', '-B', '4096', '-i', str(sensor.defaultIntf()),
                                 '-w', str(root / 'capture.pcap')], stdout=subprocess.DEVNULL, stderr=handle)
        time.sleep(.5)
        if recorder.poll() is not None:
            raise RuntimeError('Capture did not start')
        started = time.time()
        window_start = int(math.ceil((started + 5) / 60) * 60)
        actor_code = '''import socket,time,sys,json
start=int(sys.argv[1])
def connect(ip,port):
 s=socket.socket();s.settimeout(.5)
 try:
  s.connect((ip,port));s.sendall(b'N'*96);s.recv(1024)
 except (ConnectionError,TimeoutError,OSError):pass
 finally:s.close()
connect('10.123.0.12',5000)
while time.time()<start+2:time.sleep(.05)
for i in range(4):connect('10.123.0.12',5000);time.sleep(.1)
while time.time()<start+20:time.sleep(.05)
for ip in ('10.123.0.12','10.123.0.13'):
 for port in range(10001,10009):connect(ip,port)
while time.time()<start+61:time.sleep(.05)
connect('10.123.0.12',5000)
print(json.dumps({'normal_connections':4,'controlled_closed_port_attempts':16}),flush=True)
'''
        handle = (root / 'actor.log').open('w'); handles.append(handle)
        actor = hosts[0].popen(['/usr/bin/python3', '-u', '-c', actor_code, str(window_start)], stdout=handle, stderr=subprocess.STDOUT)
        processes.append(actor)
        print(json.dumps(dict(event='capturing', bridge=bridge, fully_observed_window_start=window_start,
                              expected_finish=window_start+63)), flush=True)
        while time.time() < window_start + 63:
            if recorder.poll() is not None or responder.poll() is not None:
                raise RuntimeError('Sensor/responder stopped early')
            time.sleep(.5)
        actor.wait(timeout=5)
        if actor.returncode:
            raise RuntimeError('Controlled traffic process failed')
        recorder.send_signal(signal.SIGINT)
        recorder.wait(timeout=10)
        stopped = time.time()
        text = (root / 'tcpdump.log').read_text()
        match = re.search(r'(\d+) packets dropped by kernel', text)
        drops = int(match.group(1)) if match else None
        metadata = dict(schema_version='automud.gnn-live-capture.v1', source='isolated_live_mininet', bridge=bridge,
            capture_started_at=started, capture_stopped_at=stopped, window_start=window_start, window_end=window_start+60,
            capture_drops=drops, complete=started < window_start and stopped >= window_start+60 and drops == 0,
            inventory=[dict(device_id='engineering-'+name, device_type=kind, mac=host.MAC(),
                            addresses=[dict(ip=host.IP(), start=int(started//60)*60, end=None)])
                       for name, kind, host in zip(('camera','hub','plug'),('camera','hub','plug'),hosts)],
            purpose='ML extraction/API parity; no accuracy or SDN enforcement claim')
        (root / 'capture.json').write_text(json.dumps(metadata, indent=2)+'\n')
        if not metadata['complete']:
            raise RuntimeError('Live capture is incomplete or has unknown/nonzero loss')
        return metadata
    finally:
        for process in processes:
            if process.poll() is None: process.terminate()
        for process in processes:
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
        if recorder and recorder.poll() is None:
            recorder.send_signal(signal.SIGINT)
            try: recorder.wait(timeout=5)
            except subprocess.TimeoutExpired: recorder.kill(); recorder.wait()
        for handle in handles: handle.close()
        net.stop()  # Only this helper's net/bridge; no global Mininet cleanup.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    print(json.dumps(capture(args.out), indent=2))

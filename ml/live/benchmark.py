"""Bounded API throughput probe using explicitly synthetic engineering inputs."""
import copy
import json
from pathlib import Path
import threading
import time
from ml.schema import require
from ml.live.client import Client
from ml.live.engine import LiveEngine
from ml.live.examples import example_window
from ml.live.server import Server


def benchmark(out, windows=60, devices=12):
    require(1 <= windows <= 120 and 2 <= devices <= 32, 'Benchmark bounds exceeded')
    out = Path(out).resolve()
    require(not out.exists(), 'Benchmark directory already exists')
    out.mkdir(parents=True)
    root = Path(__file__).resolve().parents[2]
    config = dict(_root=str(root), bundle='models/gnn', allowed_bundle_roots=['models'],
                  state_file=str(out / 'state.json'), torch_threads=1, device='cpu',
                  api_token_env='AUTOMUD_GNN_BENCHMARK_API_TOKEN')
    began = time.perf_counter()
    engine = LiveEngine(config)
    load = time.perf_counter() - began
    server = Server(('127.0.0.1', 0), engine)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    client = Client(f'http://127.0.0.1:{server.server_address[1]}')
    first = int(time.time() // 60) * 60 - windows * 60
    kinds = ('camera', 'hub', 'plug', 'light', 'speaker', 'printer')
    inventory = [dict(device_id=f'engineering-device-{i}', device_type=kinds[i % len(kinds)],
                      addresses=[dict(ip=f'10.0.0.{11+i}', start=first, end=None)]) for i in range(devices)]
    latencies = []
    try:
        for index in range(windows):
            start = first + index * 60
            window = example_window(start, 'engineering-benchmark', 'benchmark-1')
            window['inventory'] = inventory
            template = window['telemetry'][0]
            window['telemetry'] = []
            for i in range(devices):
                row = copy.deepcopy(template)
                row.update(uid=f'engineering-{index}-{i}', orig_h=inventory[i]['addresses'][0]['ip'],
                           resp_h=inventory[(i+1) % devices]['addresses'][0]['ip'], resp_p=8080 + i,
                           orig_ip_bytes=400 + 20*i, resp_ip_bytes=600 + 20*i)
                window['telemetry'].append(row)
            began = time.perf_counter()
            response = client.submit(window)
            latencies.append(time.perf_counter() - began)
            require(len(response['devices']) == devices, 'Benchmark lost device records')
        values = sorted(latencies)
        try:
            import resource
            rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        except ImportError:
            rss_mb = None
        report = dict(schema_version='automud.gnn-throughput.v1', purpose='Synthetic API/CPU capacity probe, not detection accuracy',
            windows=windows, devices=devices, records=windows*devices, model_load_seconds=load,
            http_seconds=dict(p50=values[len(values)//2], p95=values[int((len(values)-1)*.95)], max=max(values)),
            keeps_up_with_60_second_cadence=max(values) < 60, state_bytes=(out / 'state.json').stat().st_size,
            process_peak_rss_mb=rss_mb, model=engine.model_info(), training_invocations=0, accuracy_metrics_computed=False)
        (out / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        return report
    finally:
        server.shutdown(); server.server_close(); worker.join(10)
        engine.close()

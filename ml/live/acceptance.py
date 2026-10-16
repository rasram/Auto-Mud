"""Live captured packet -> Zeek -> stable HTTP evidence acceptance, without SDN."""
import copy
import json
import os
from pathlib import Path
import secrets
import threading
import time
from jsonschema import Draft202012Validator
from ml.schema import read_json, read_jsonl, require, file_hash
from ml.dataset_prep.extract import extract
from ml.ab_targets.graphs import build_v4
from ml.live.bundles import export_bundle
from ml.live.client import Client
from ml.live.engine import LiveEngine
from ml.live.server import Server


def validate_capture(capture_dir, out, zeek='/opt/zeek/bin/zeek'):
    capture_dir, out = Path(capture_dir).resolve(), Path(out).resolve()
    require(not out.exists(), 'Acceptance output already exists; choose a new directory')
    metadata = read_json(capture_dir / 'capture.json')
    require(metadata['complete'] and metadata['capture_drops'] == 0, 'Expected loss-free fully observed live capture')
    out.mkdir(parents=True)
    telemetry_path = extract([capture_dir / 'capture.pcap'], out / 'zeek', zeek)
    first = int(metadata['capture_started_at'] // 60) * 60
    end = metadata['window_end']
    rows = [r for r in read_jsonl(telemetry_path) if first <= r['window_start'] < end]
    require(any(r['window_start'] == metadata['window_start'] for r in rows), 'No telemetry for fully observed minute')
    scan = [r for r in rows if r['window_start'] == metadata['window_start'] and 10001 <= r.get('resp_p', 0) <= 10008]
    require(len(scan) >= 16 and all(r.get('tcp_syn_observed') and r['failed'] for r in scan),
            'Controlled closed-port attempts were not observed correctly')
    inventory = copy.deepcopy(metadata['inventory'])
    for device in inventory:
        for address in device['addresses']:
            address['end'] = end
    manifest = dict(schema_version='automud.graph.v3', run_id='live-mininet-acceptance', session_id='capture-1',
                    source='live_zeek', normal=False, capture_complete=True, replay_speed=1,
                    start=first, end=end, inventory=inventory,
                    outages=[dict(start=first, end=metadata['window_start'])] if first < metadata['window_start'] else [])
    offline = list(build_v4(rows, manifest))
    root = Path(__file__).resolve().parents[2]
    config = dict(_root=str(root), bundle='models/gnn', allowed_bundle_roots=['models', str(out)],
                  state_file=str(out / 'state.json'), torch_threads=1, device='cpu',
                  admin_token_env='AUTOMUD_GNN_ACCEPTANCE_ADMIN_TOKEN', api_token_env='AUTOMUD_GNN_ACCEPTANCE_API_TOKEN')
    token = secrets.token_urlsafe(24)
    old = os.environ.get(config['admin_token_env'])
    os.environ[config['admin_token_env']] = token
    began = time.perf_counter()
    engine = LiveEngine(config)
    if engine.active.adapter=='supervised-direct.v1':
        from ml.supervised.graphs import build_graphs
        offline=list(build_graphs(rows,manifest,engine.active.profile))
    load_seconds = time.perf_counter() - began
    server = Server(('127.0.0.1', 0), engine)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    client = Client(f'http://127.0.0.1:{server.server_address[1]}')
    admin = Client(client.url, token=token)
    output_schema = Draft202012Validator(read_json(root / 'configs/gnn/live/evidence.schema.json'))
    latencies = []
    compared = 0
    max_error = 0.
    response = None
    try:
        require(client.health()['ready'], 'HTTP service is not ready')
        for reference in offline:
            start = reference['window_start']
            window = dict(schema_version='automud.live-window.v1', observation_kind='engineering', run_id=manifest['run_id'], session_id=manifest['session_id'],
                          sensor_id='live-zeek-1', inventory_version='capture-inventory-1', window_start=start, window_end=start+60,
                          watermark=start+60, inventory=metadata['inventory'],
                          health=dict(complete=start >= metadata['window_start'], sensor_healthy=True, clock_synchronized=True,
                                      capture_drops=0, unavailable_device_ids=[]),
                          telemetry=[r for r in rows if r['window_start'] == start])
            began = time.perf_counter()
            response = client.submit(window)
            latencies.append(time.perf_counter() - began)
            output_schema.validate(response)
            actual = next(iter(engine.streams.values()))['last_graph']
            for node, expected in zip(actual['nodes'], reference['nodes']):
                for key in ('device_id', 'features', 'feature_mask', 'temporal_history', 'active', 'available'):
                    require(node[key] == expected[key], 'Streaming/offline feature mismatch: ' + key)
            require(actual['edges'] == reference['edges'], 'Streaming/offline edge mismatch')
            reference['observation_clock'] = dict(schema_version='automud.observation-clock.v1', mode='live_utc', window_start=start)
            expected_scores = engine.active.score_graph(reference)
            for actual_row, expected_row in zip(response['devices'], expected_scores['devices']):
                for flag in ('behavioral_flag', 'link_flag'):
                    require(actual_row[flag] is expected_row[flag], 'Live API/offline decision mismatch')
                    compared += 1
                for score in ('behavioral_score', 'link_anomaly'):
                    require((actual_row[score] is None) == (expected_row[score] is None), 'Live score availability mismatch')
                    if actual_row[score] is not None:
                        error = abs(actual_row[score] - expected_row[score])
                        max_error = max(max_error, error)
                        require(error <= 1e-4, 'Live API/offline score mismatch')
        require(client.submit(window) == response, 'HTTP retry is not idempotent')
        baseline = client.call('/v1/model')
        candidate = export_bundle(root / 'models/gnn', None,
                                  out / 'candidate', 'acceptance-same-weights')
        staged = admin.call('/v1/models/stage', {'bundle': candidate['path']})
        admin.call('/v1/models/activate', {'bundle_id': staged['model']['bundle_id']})
        require(client.call('/v1/model')['bundle_version'] == 'acceptance-same-weights', 'Activation failed')
        admin.call('/v1/models/rollback', {'bundle_id': baseline['bundle_id']})
        require(client.call('/v1/model') == baseline, 'Rollback did not restore baseline')
        server.shutdown(); server.server_close(); worker.join(10)
        engine.close()
        restored = LiveEngine(config)
        try:
            require(restored.submit(window) == (response, True), 'Durable restart lost accepted response/history')
        finally:
            restored.close()
        report = dict(schema_version='automud.gnn-live-acceptance.v1', status='passed',
            purpose='ML software/extraction/API handoff; not classifier accuracy, Ryu or physical-device validation',
            captured_packets_sha256=file_hash(capture_dir / 'capture.pcap'), zeek_policy_sha256=file_hash(root / 'network/zeek/automud-window.zeek'),
            capture_drops=metadata['capture_drops'], telemetry_rows=len(rows), fully_observed_windows=1,
            controlled_closed_port_rows=len(scan), processed_windows=len(offline), exact_feature_and_edge_parity=True,
            flag_checks=compared, max_score_error=max_error, http_seconds=latencies,
            model_load_seconds=load_seconds, durable_restart=True, idempotency=True, stage_activate_rollback=True,
            model=baseline, training_invocations=0, accuracy_metrics_computed=False)
        (out / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        return report
    finally:
        server.shutdown(); server.server_close(); worker.join(10)
        engine.close()
        if old is None:
            os.environ.pop(config['admin_token_env'], None)
        else:
            os.environ[config['admin_token_env']] = old

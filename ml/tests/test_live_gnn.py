"""Deployment semantics; engineering traffic is not an accuracy evaluation."""
import copy
import json
from pathlib import Path
import threading
import socket
import time
import subprocess
import sys
import signal
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
import torch
from ml.ab_targets.graphs import build_v4
from ml.clock import native_offsets
from ml.inference import GNNBundle
from ml.live.bundles import export_bundle
from ml.live.contracts import validate_window
from ml.live.engine import LiveEngine
from ml.live.examples import example_window
from ml.live.graphs import StreamingGraph
from ml.live.server import Server
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
START = 1700000040


@pytest.fixture
def config(tmp_path):
    return dict(_root=str(ROOT), bundle='models/gnn', allowed_bundle_roots=['models', str(tmp_path)],
                state_file='', torch_threads=1, device='cpu', dedup_windows=3, max_streams=2,
                admin_token_env='AUTOMUD_GNN_TEST_ADMIN_TOKEN', api_token_env='AUTOMUD_GNN_TEST_API_TOKEN')


@pytest.fixture
def engine(config):
    model = LiveEngine(config, now=lambda: START + 100000)
    yield model
    model.close()


def clean_node(node):
    return {k: node[k] for k in ('device_id', 'device_type', 'features', 'feature_mask', 'temporal_history', 'available', 'active')}


def test_incremental_features_equal_offline_over_hour_and_resume():
    windows = [example_window(START + 60 * i) for i in range(80)]
    # Long-running UID, new external peer, receiving flows and quiet intervals.
    for i, w in enumerate(windows):
        if i % 7 == 0:
            w['telemetry'] = []
        elif i % 3:
            w['telemetry'][0].update(uid='persistent', flow_start=START + 61, new_flow=i == 1,
                                     observed_duration=min(60., i * 60.))
        else:
            w['telemetry'][0]['resp_h'] = '203.0.113.1'
    manifest = dict(schema_version='automud.graph.v3', run_id='engineering-demo', session_id='demo-1',
        source='live_zeek', start=START, end=START + 80 * 60, normal=False, capture_complete=True,
        replay_speed=1, inventory=copy.deepcopy(windows[0]['inventory']))
    for device in manifest['inventory']:
        for address in device['addresses']:
            address['end'] = manifest['end']
    expected = list(build_v4([r for w in windows for r in w['telemetry']], manifest))
    builder = StreamingGraph()
    for i, (window, reference) in enumerate(zip(windows, expected)):
        if i == 41:
            builder = StreamingGraph.restore(json.loads(json.dumps(builder.dump())))
        actual, state = builder.build(validate_window(window, now=START + 100000))
        assert [clean_node(n) for n in actual['nodes']] == [clean_node(n) for n in reference['nodes']]
        assert actual['edges'] == reference['edges']
        assert native_offsets(actual) == {n['device_id']: 0 for n in actual['nodes']}
    assert state['history']['demo-camera']['fully_warmed']


def test_live_clock_matches_native_encoder_with_identical_utc(engine):
    graph, _ = StreamingGraph().build(example_window(START),profile=engine.active.profile)
    captured = copy.deepcopy(graph)
    captured.pop('observation_clock')
    captured['source_interval_id'] = '|'.join(f"{n['device_id']}:captured:{START}:{START+60}" for n in graph['nodes'] if n['device_type'] != 'external_service')
    assert engine.active.score_graph(graph) == engine.active.score_graph(captured)


def test_idempotency_conflict_and_out_of_order_are_transactional(engine):
    first = example_window(START)
    original, replay = engine.submit(first)
    assert not replay
    assert engine.submit(copy.deepcopy(first)) == (original, True)
    conflicting = copy.deepcopy(first)
    conflicting['telemetry'][0]['orig_ip_bytes'] += 1
    with pytest.raises(ValueError, match='Conflicting duplicate'):
        engine.submit(conflicting)
    before = engine.streams[next(iter(engine.streams))]['builder'].dump()
    with pytest.raises(ValueError, match='Out-of-order'):
        engine.submit(example_window(START - 60))
    assert engine.streams[next(iter(engine.streams))]['builder'].dump() == before


@pytest.mark.parametrize('field,value', [('complete', False), ('sensor_healthy', False), ('clock_synchronized', False), ('capture_drops', None), ('capture_drops', 1)])
def test_bad_observation_never_becomes_normal(engine, field, value):
    request = example_window(START)
    request['health'][field] = value
    response, _ = engine.submit(request)
    for row in response['devices']:
        assert row['status'] == 'unavailable'
        assert row['behavioral_score'] is None and row['behavioral_flag'] is None
        assert row['link_anomaly'] is None and row['link_flag'] is None


def test_idle_device_is_distinct_from_sensor_outage(engine):
    request = example_window(START)
    request['telemetry'] = []
    response, _ = engine.submit(request)
    assert all(r['status'] == 'inactive' for r in response['devices'])
    assert response['health']['sensor_healthy']


def test_gap_outage_and_binding_change_reset_history(engine):
    engine.submit(example_window(START))
    response, _ = engine.submit(example_window(START + 120))
    assert response['state']['reset_reason'] == 'observation_gap'
    assert all(r['history']['prior_windows'] == 0 for r in response['devices'])
    changed = example_window(START + 180)
    changed['inventory'][0]['addresses'][0]['ip'] = '10.0.0.13'
    response, _ = engine.submit(changed)
    assert response['state']['reset_device_ids'] == ['demo-camera']
    bad = example_window(START + 240)
    bad['health']['unavailable_device_ids'] = ['demo-hub']
    engine.submit(bad)
    restored, _ = engine.submit(example_window(START + 300))
    assert next(r for r in restored['devices'] if r['device_id'] == 'demo-hub')['history']['prior_windows'] == 0


@pytest.mark.parametrize('kind', ['duplicate_uid', 'other_window', 'ambiguous_ip', 'future', 'wrong_schema'])
def test_invalid_window_rejected_before_state_change(engine, kind):
    w = example_window(START)
    if kind == 'duplicate_uid': w['telemetry'].append(copy.deepcopy(w['telemetry'][0]))
    elif kind == 'other_window': w['telemetry'][0]['window_start'] += 60
    elif kind == 'ambiguous_ip': w['inventory'][1]['addresses'][0]['ip'] = '10.0.0.11'
    elif kind == 'future': w = example_window(START + 200000)
    else: w['schema_version'] = 'unsupported'
    with pytest.raises(ValueError): engine.submit(w)
    assert not engine.streams


def test_restart_preserves_history_and_duplicate_outputs(config, tmp_path):
    config['state_file'] = str(tmp_path / 'state.json')
    first = LiveEngine(config, now=lambda: START + 100000)
    original, _ = first.submit(example_window(START))
    first.close()
    second = LiveEngine(config, now=lambda: START + 100000)
    assert second.submit(example_window(START)) == (original, True)
    result, _ = second.submit(example_window(START + 60))
    assert all(r['history']['prior_windows'] == 1 for r in result['devices'])
    second.close()


def test_failed_persistence_does_not_accept_window(engine, monkeypatch):
    def broken(_): raise OSError('simulated storage failure')
    monkeypatch.setattr(engine, '_save', broken)
    with pytest.raises(OSError): engine.submit(example_window(START))
    assert not engine.streams


def make_candidate(tmp_path):
    out = tmp_path / 'candidate'
    export_bundle(ROOT / 'models/gnn', None, out, 'candidate-test')
    return out


def test_stage_activate_history_resume_and_rollback(engine, tmp_path):
    baseline = engine.model_info()
    original, _ = engine.submit(example_window(START))
    path = make_candidate(tmp_path)
    staged = engine.stage(str(path))
    assert engine.model_info() == baseline
    activated = engine.activate(staged['model']['bundle_id'])
    assert activated['boundary'] == 'between_completed_windows'
    current, _ = engine.submit(example_window(START + 60))
    assert current['model']['bundle_version'] == 'candidate-test'
    assert current['provenance'] == original['provenance']
    assert all(r['history']['prior_windows'] == 1 for r in current['devices'])
    assert engine.submit(example_window(START)) == (original, True)
    engine.rollback()
    assert engine.model_info() == baseline


def test_rejected_candidate_keeps_active_bundle(engine, tmp_path):
    baseline = engine.model_info()
    path = make_candidate(tmp_path)
    manifest = json.loads((path / 'manifest.json').read_text())
    manifest['input_schema'] = 'automud.changed.v9'
    (path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='contract'): engine.stage(str(path))
    assert engine.model_info() == baseline
    with pytest.raises(ValueError, match='approved roots'): engine.stage('/outside/model')


def test_activation_waits_for_current_window(engine, tmp_path, monkeypatch):
    staged = engine.stage(str(make_candidate(tmp_path)))
    old = engine.model_info()['bundle_id']
    began, release, activated = threading.Event(), threading.Event(), threading.Event()
    score = engine.active.score_graph
    def paused(graph):
        began.set()
        assert release.wait(10)
        return score(graph)
    monkeypatch.setattr(engine.active, 'score_graph', paused)
    result = []
    t = threading.Thread(target=lambda: result.append(engine.submit(example_window(START))[0]))
    t.start()
    assert began.wait(10)
    a = threading.Thread(target=lambda: (engine.activate(staged['model']['bundle_id']), activated.set()))
    a.start()
    assert not activated.wait(.05)
    release.set()
    t.join(10); a.join(10)
    assert not t.is_alive() and not a.is_alive()
    assert result[0]['model']['bundle_id'] == old and activated.is_set()


def test_http_api_authorization_schema_and_idempotency(engine, monkeypatch):
    server = Server(('127.0.0.1', 0), engine)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f'http://127.0.0.1:{server.server_address[1]}'
    def call(path, value=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token: headers['Authorization'] = 'Bearer ' + token
        request = Request(base + path, data=json.dumps(value).encode() if value is not None else None, headers=headers)
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read()), response.headers
    try:
        assert call('/readyz')[1]['ready']
        assert call('/v1/contracts')[1]['input']['$id'] == 'urn:automud:live-window:v1'
        with pytest.raises(HTTPError) as denied: call('/v1/models/rollback', {})
        assert denied.value.code == 403
        original = call('/v1/windows', example_window(START))
        duplicate = call('/v1/windows', example_window(START))
        assert original[1] == duplicate[1] and duplicate[2]['X-AutoMUD-Replay'] == 'true'
        monkeypatch.setenv('AUTOMUD_GNN_TEST_API_TOKEN', 'test-api-token')
        with pytest.raises(HTTPError) as denied: call('/healthz')
        assert denied.value.code == 401
        assert call('/healthz', token='test-api-token')[1]['ready']
        monkeypatch.setenv('AUTOMUD_GNN_TEST_ADMIN_TOKEN', 'test-admin-token')
        with pytest.raises(HTTPError) as denied: call('/v1/sessions/reset', dict(run_id='engineering-demo', session_id='demo-1', sensor_id='zeek-1'), token='wrong')
        assert denied.value.code == 401
        assert call('/v1/sessions/reset', dict(run_id='engineering-demo', session_id='demo-1', sensor_id='zeek-1'), token='test-admin-token')[1]['existed']
    finally:
        server.shutdown(); server.server_close(); worker.join(10)


def test_output_schema_and_unknown_device_fallback(engine):
    output, _ = engine.submit(example_window(START))
    schema = json.loads((ROOT / 'configs/gnn/live/evidence.schema.json').read_text())
    Draft202012Validator(schema).validate(output)
    assert output['observation_kind'] == 'engineering' and output['diagnostic']
    scope = next(r for r in output['devices'] if r['device_id'] == 'demo-camera')['calibration_scope']['a']
    assert scope['scope'] == 'frozen_selection_and_clean_calibration' and not scope['fallback']
    assert not next(r for r in output['devices'] if r['device_id']=='demo-camera')['profile_support']['known_device']
    unknown = example_window(START + 60)
    unknown['inventory'][0]['device_type'] = 'unknown'
    output, _ = engine.submit(unknown)
    assert next(r for r in output['devices'] if r['device_id'] == 'demo-camera')['calibration_scope']['a']['value']==scope['value']


def test_two_services_cannot_share_durable_state(config, tmp_path):
    config['state_file'] = str(tmp_path / 'owned-state.json')
    first = LiveEngine(config)
    try:
        with pytest.raises(ValueError, match='already in use'): LiveEngine(config)
    finally:
        first.close()
    second = LiveEngine(config)
    second.close()


def test_active_model_and_history_survive_restart_after_swap(config, tmp_path):
    config['state_file'] = str(tmp_path / 'swap-state.json')
    first = LiveEngine(config, now=lambda: START + 100000)
    first.submit(example_window(START))
    staged = first.stage(str(make_candidate(tmp_path)))
    first.activate(staged['model']['bundle_id'])
    first.close()
    second = LiveEngine(config, now=lambda: START + 100000)
    try:
        assert second.model_info()['bundle_version'] == 'candidate-test'
        output, _ = second.submit(example_window(START + 60))
        assert all(r['history']['prior_windows'] == 1 for r in output['devices'])
        second.rollback()
        assert second.model_info()['bundle_version'] == GNNBundle(ROOT/'models/gnn').bundle_version
    finally:
        second.close()


def test_evicted_retry_is_rejected_instead_of_rescored(engine):
    for i in range(4): engine.submit(example_window(START + 60*i))
    with pytest.raises(ValueError, match='Out-of-order'): engine.submit(example_window(START))


def test_expired_or_midminute_lease_is_unscored(engine):
    w = example_window(START)
    w['inventory'][0]['addresses'][0]['end'] = START+30
    result, _ = engine.submit(w)
    camera = next(r for r in result['devices'] if r['device_id'] == 'demo-camera')
    assert camera['status'] == 'unavailable' and camera['behavioral_flag'] is None


def test_manifest_modified_after_loading_is_rejected(engine, tmp_path):
    path = make_candidate(tmp_path)
    staged = engine.stage(str(path))
    original = engine.model_info()
    with (path / 'manifest.json').open('a') as f: f.write(' ')
    with pytest.raises(ValueError, match='manifest changed'): engine.activate(staged['model']['bundle_id'])
    assert engine.model_info() == original


def test_nonfinite_candidate_weights_rejected_without_activation(engine, tmp_path):
    checkpoint = tmp_path / 'bad.pt'
    path=make_candidate(tmp_path)
    artifact = torch.load(path/'detector.pt', map_location='cpu', weights_only=True)
    next(iter(artifact['state_dict'].values())).fill_(float('nan'))
    torch.save(artifact,path/'detector.pt')
    from ml.schema import file_hash
    manifest=json.loads((path/'manifest.json').read_text())
    entry=next(e for e in manifest['files'] if e['path']=='detector.pt')
    entry.update(bytes=(path/'detector.pt').stat().st_size,sha256=file_hash(path/'detector.pt'))
    (path/'manifest.json').write_text(json.dumps(manifest))
    original = engine.model_info()
    with pytest.raises(ValueError, match='Nonfinite supervised weights'):
        engine.stage(str(path))
    assert engine.model_info() == original


def test_bounded_http_connections_return_busy(engine):
    engine.config['max_connections'] = 1
    server = Server(('127.0.0.1', 0), engine)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    held = socket.create_connection(server.server_address, timeout=2)
    try:
        deadline = time.monotonic()+2
        while server.slots._value != 0 and time.monotonic() < deadline: time.sleep(.01)
        assert server.slots._value == 0
        with pytest.raises(HTTPError) as busy:
            urlopen(f'http://127.0.0.1:{server.server_address[1]}/readyz', timeout=3)
        assert busy.value.code == 503
        assert not engine.streams
    finally:
        held.close(); server.shutdown(); server.server_close(); worker.join(10)


def test_model_operation_retries_do_not_toggle_rollback(engine, tmp_path):
    baseline = engine.model_info()
    staged = engine.stage(str(make_candidate(tmp_path)))
    candidate = staged['model']['bundle_id']
    engine.activate(candidate)
    assert engine.activate(candidate)['status'] == 'already_active'
    engine.rollback(baseline['bundle_id'])
    assert engine.rollback(baseline['bundle_id'])['status'] == 'already_active'
    assert engine.model_info() == baseline


@pytest.mark.skipif(sys.platform == 'win32', reason='Linux foreground launcher qualification')
def test_cli_service_launch_shutdown_and_durable_retry(config, tmp_path, monkeypatch):
    from ml.live.client import Client
    monkeypatch.delenv(config['api_token_env'], raising=False)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    config.update(project_root=str(ROOT), host='127.0.0.1', port=port,
                  state_file=str(tmp_path / 'cli-state.json'))
    path = tmp_path / 'service.json'
    path.write_text(json.dumps(config))
    client = Client(f'http://127.0.0.1:{port}', timeout=.5, retries=0)
    request = example_window(START)
    first = None
    for _ in range(2):
        process = subprocess.Popen([sys.executable, '-m', 'ml', 'serve', '--config', str(path)],
                                   cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    if client.health()['ready']: break
                except OSError:
                    pass
                assert process.poll() is None, process.communicate()[1].decode()
                assert time.monotonic() < deadline, 'CLI did not become ready'
                time.sleep(.1)
            result = client.submit(request)
            if first is None: first = result
            else: assert result == first
        finally:
            if process.poll() is None: process.send_signal(signal.SIGINT)
            try: _, errors = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()
                pytest.fail('CLI did not shut down')
            assert process.returncode == 0, errors.decode()

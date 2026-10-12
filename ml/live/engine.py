"""Transactional window processing, durable history, idempotency and swapping."""
from collections import OrderedDict, deque
import copy
import json
import os
from pathlib import Path
import threading
import time
import torch
from ml.schema import require
from ml.inference import GNNBundle
from ml.live.contracts import digest, validate_window
from ml.live.graphs import StreamingGraph


class LiveEngine:
    def __init__(self, config, now=time.time):
        self.config = config
        self.now = now
        self.lock = threading.RLock()
        self.config_root = Path(config.get('_root', '.')).resolve()
        self.roots = [(self.config_root / p).resolve() for p in config['allowed_bundle_roots']]
        self.state_path = (self.config_root / config['state_file']).resolve() if config.get('state_file') else None
        self._state_lock = None
        self.closed = False
        torch.set_num_threads(config.get('torch_threads', 1))
        self.active = self._load(config['bundle'])
        self.previous = None
        self.staged = None
        self.streams = {}
        self.stats = dict(windows=0, duplicates=0, unscored_windows=0, failures=0)
        self.latencies = deque(maxlen=1024)
        self.last_error = None
        if self.state_path:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.state_path.with_suffix('.lock').open('a+')
            try:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except ImportError:
                import msvcrt
                handle.seek(0)
                if not handle.read(1):
                    handle.write('1'); handle.flush()
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    handle.close()
                    raise ValueError('State file already in use by another service')
            except OSError:
                handle.close()
                raise ValueError('State file already in use by another service')
            self._state_lock = handle
            try:
                if self.state_path.exists():
                    self._restore(json.loads(self.state_path.read_text()))
            except Exception:
                self.close()
                raise

    def close(self):
        with self.lock:
            if self._state_lock:
                self._state_lock.close()
                self._state_lock = None
            self.closed = True

    def _load(self, path):
        root = (self.config_root / path).resolve()
        require(any(root.is_relative_to(base) for base in self.roots), 'Bundle path outside approved roots')
        require(not (root / 'EXPORT_FAILED.txt').exists(), 'Candidate export failed')
        return GNNBundle(root, self.config.get('device', 'cpu'), allow_candidate=True)

    def model_info(self, model=None):
        model = model or self.active
        return dict(bundle_id=model.bundle_id, bundle_version=model.bundle_version,
                    a_checkpoint=model.inputs['selected-a.pt'], b_checkpoint=model.inputs['frozen-b.pt'])

    def _payload(self, streams=None, active=None, previous=False):
        streams = self.streams if streams is None else streams
        model = active or self.active
        prior = self.previous if previous is False else previous
        return dict(schema_version='automud.live-state.v1', active=dict(path=str(model.root), bundle_id=model.bundle_id),
                    previous=dict(path=str(prior.root), bundle_id=prior.bundle_id) if prior else None,
                    streams={key: dict(builder=s['builder'].dump(), cache=list(s['cache'].items()), last_graph=s['last_graph'],
                                       last_response=s['last_response']) for key, s in streams.items()})

    def _save(self, payload):
        if not self.state_path:
            return
        content = json.dumps(payload, allow_nan=False, separators=(',', ':'))
        require(len(content.encode()) <= self.config.get('max_state_bytes', 16777216), 'Durable state size limit exceeded')
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix('.tmp')
        with temporary.open('w', encoding='utf-8') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.state_path)

    def _restore(self, payload):
        require(payload['schema_version'] == 'automud.live-state.v1', 'Unsupported durable state')
        active = self._load(payload['active']['path'])
        require(active.bundle_id == payload['active']['bundle_id'], 'Persisted active bundle changed')
        previous = None
        if payload['previous']:
            previous = self._load(payload['previous']['path'])
            require(previous.bundle_id == payload['previous']['bundle_id'], 'Persisted rollback bundle changed')
        self.active, self.previous = active, previous
        require(len(payload['streams']) <= self.config.get('max_streams', 8), 'Persisted session limit exceeded')
        for key, state in payload['streams'].items():
            self.streams[key] = dict(builder=StreamingGraph.restore(state['builder']),
                                     cache=OrderedDict(state['cache']), last_graph=state['last_graph'], last_response=state['last_response'])

    def submit(self, raw):
        window = validate_window(raw, now=self.now(), future_skew_seconds=self.config.get('future_skew_seconds', 2))
        key = digest([window['run_id'], window['session_id'], window['sensor_id']])
        request_hash = digest(window)
        start_key = str(window['window_start'])
        with self.lock:
            require(not self.closed, 'Engine is closed')
            began = time.perf_counter()
            state = self.streams.get(key)
            if state and start_key in state['cache']:
                saved = state['cache'][start_key]
                require(saved['request_hash'] == request_hash, 'Conflicting duplicate window')
                self.stats['duplicates'] += 1
                return copy.deepcopy(saved['response']), True
            require(state is not None or len(self.streams) < self.config.get('max_streams', 8), 'Active session limit exceeded; reset an unused session')
            candidate = copy.deepcopy(state) if state else dict(builder=StreamingGraph(self.config.get('max_peers_per_device', 4096)),
                                                               cache=OrderedDict(), last_graph=None, last_response=None)
            graph, history = candidate['builder'].build(window)
            self.active.verify_inputs()
            response = self.active.score_graph(graph)
            elapsed = time.perf_counter() - began
            response.update(sensor_id=window['sensor_id'], inventory_version=window['inventory_version'],
                            observation_kind=window['observation_kind'], diagnostic=window['observation_kind'] == 'engineering',
                            observation_id=digest([key, window['window_start']]), model=self.model_info(),
                            health=dict(window['health'], identity_unscored_device_ids=[n['device_id'] for n in graph['nodes']
                                       if n['device_type'] != 'external_service' and not n['available']],
                                        received_at=self.now(), processing_seconds=elapsed), state=history)
            for row in response['devices']:
                row['history'] = history['history'].get(row['device_id'])
            candidate['cache'][start_key] = dict(request_hash=request_hash, response=response)
            while len(candidate['cache']) > self.config.get('dedup_windows', 8):
                candidate['cache'].popitem(last=False)
            candidate['last_graph'], candidate['last_response'] = graph, response
            next_streams = dict(self.streams, **{key: candidate})
            self._save(self._payload(next_streams))
            self.streams = next_streams
            self.stats['windows'] += 1
            self.stats['unscored_windows'] += not window['health']['complete'] or not window['health']['sensor_healthy'] or not window['health']['clock_synchronized'] or window['health']['capture_drops'] != 0
            self.latencies.append(elapsed)
            self.last_error = None
            return copy.deepcopy(response), False

    def stage(self, path):
        # Loading cannot alter active state. HTTP queue bounds and admin auth
        # limit concurrent staging; activation is separately serialized.
        with self.lock:
            require(not self.closed, 'Engine is closed')
            model = self._load(path)
            require(model.bundle_id != self.active.bundle_id, 'Bundle is already active')
            if self.streams:
                graph = next(iter(self.streams.values()))['last_graph']
            else:
                from ml.live.examples import example_window
                graph, _ = StreamingGraph().build(example_window(int(self.now() // 60) * 60 - 60))
            probe = model.score_graph(graph)
            require(probe['schema_version'] == 'automud.gnn-evidence.v1' and all('behavioral_flag' in r and 'link_flag' in r for r in probe['devices']),
                    'Candidate output contract differs')
            model.verify_inputs()
            self.staged = model
            return dict(status='staged', model=self.model_info(model), accuracy_validated=False)

    def activate(self, bundle_id):
        with self.lock:
            require(not self.closed, 'Engine is closed')
            if self.active.bundle_id == bundle_id:
                return dict(status='already_active', model=self.model_info(), boundary='between_completed_windows')
            require(self.staged is not None and self.staged.bundle_id == bundle_id, 'No matching staged candidate')
            self.staged.verify_inputs()
            self._save(self._payload(active=self.staged, previous=self.active))
            self.previous, self.active, self.staged = self.active, self.staged, None
            return dict(status='activated', model=self.model_info(), rollback=self.model_info(self.previous),
                        boundary='between_completed_windows', feature_history_preserved=True)

    def rollback(self, bundle_id=None):
        with self.lock:
            require(not self.closed, 'Engine is closed')
            if bundle_id is not None and self.active.bundle_id == bundle_id:
                return dict(status='already_active', model=self.model_info(), boundary='between_completed_windows')
            require(self.previous is not None, 'No rollback bundle available')
            require(bundle_id is None or self.previous.bundle_id == bundle_id, 'Requested rollback bundle is not available')
            self.previous.verify_inputs()
            self._save(self._payload(active=self.previous, previous=self.active))
            self.active, self.previous = self.previous, self.active
            self.staged = None
            return dict(status='rolled_back', model=self.model_info(), boundary='between_completed_windows')

    def reset_session(self, run_id, session_id, sensor_id):
        with self.lock:
            require(not self.closed, 'Engine is closed')
            key = digest([run_id, session_id, sensor_id])
            next_streams = dict(self.streams)
            found = next_streams.pop(key, None) is not None
            self._save(self._payload(next_streams))
            self.streams = next_streams
            return dict(status='reset', existed=found, next_window='cold_start')

    def health(self):
        with self.lock:
            try:
                self.active.verify_inputs()
                ready, reason = not self.closed, 'Engine is closed' if self.closed else None
            except Exception as error:
                ready, reason = False, str(error)
            times = sorted(self.latencies)
            percentile = lambda p: times[min(len(times) - 1, int((len(times) - 1) * p))] if times else None
            streams = []
            for state in self.streams.values():
                response = state['last_response']
                h = response['health']
                streams.append(dict(run_id=response['run_id'], session_id=response['session_id'], sensor_id=response['sensor_id'],
                    last_window_end=response['window_end'], stale=self.now() - response['window_end'] > self.config.get('stale_after_seconds', 180),
                    observation_healthy=h['complete'] and h['sensor_healthy'] and h['clock_synchronized'] and h['capture_drops'] == 0))
            return dict(schema_version='automud.gnn-health.v1', ready=ready, reason=reason,
                        model=self.model_info(), streams=streams, stats=self.stats.copy(), last_error=self.last_error,
                        processing_seconds=dict(p50=percentile(.5), p95=percentile(.95), max=max(times) if times else None))

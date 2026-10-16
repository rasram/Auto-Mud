"""Incremental selected v4 features, reusing the exact offline operations."""
from collections import Counter, defaultdict, deque
from copy import deepcopy as copy_graph
from ml.schema import resolve_device, require
from ml.graph.build import features
from ml.graph.context import extend_features, service_id
from ml.ab_targets.graphs import receiver_features
from ml.ab_targets.schema import FEATURES, TEMPORAL_FEATURES, VERSION, SCHEMA_HASH
from ml.live.contracts import observed_manifest, digest


class StreamingGraph:
    def __init__(self, max_peers=4096):
        self.max_peers = max_peers
        self.devices = {}
        self.edges = set()
        self.last_window = None
        self.epoch_start = None
        self.epoch = 0
        self.model_past = deque(maxlen=15)
        self.model_profile_id = None

    @staticmethod
    def new_device(identity, start):
        return dict(identity=identity, epoch_start=start, destinations=set(), temporal={},
                    peers=set(), prior=deque(maxlen=5), past=deque(maxlen=15))

    def build(self, window, profile=None):
        start = window['window_start']
        reason = None
        if self.last_window is not None:
            require(start > self.last_window, 'Out-of-order window')
            if start != self.last_window + 60:
                self.devices.clear()
                self.model_past.clear()
                self.edges.clear()
                self.epoch += 1
                reason = 'observation_gap'
                self.epoch_start = start
        if self.epoch_start is None:
            self.epoch_start = start
            reason = 'cold_start'
        manifest, unavailable = observed_manifest(window)
        model_reset = None
        if profile is not None:
            from ml.supervised.graphs import profile_id
            current_profile = profile_id(profile)
            if current_profile != self.model_profile_id:
                self.model_past.clear()
                for state in self.devices.values(): state['flow'] = {}
                model_reset = 'profile_changed_or_initial_supervised_start'
            self.model_profile_id = current_profile
        else:
            self.model_past.clear()
            self.model_profile_id = None
        grouped = defaultdict(list)
        pairs = defaultdict(list)
        for row in window['telemetry']:
            orig = resolve_device(manifest, row['orig_h'], row.get('orig_mac'), start)
            resp = resolve_device(manifest, row['resp_h'], row.get('resp_mac'), start)
            if orig:
                grouped[orig].append((row, True))
            if resp and resp != orig:
                grouped[resp].append((row, False))
            if orig and resp and orig != resp:
                pairs[orig, resp].append(row)
            elif orig:
                pairs[orig, service_id(row)].append(row)
            elif resp:
                pairs[service_id(row), resp].append(row)
        nodes = []
        live_ids = {d['device_id'] for d in manifest['inventory']}
        self.devices = {k: v for k, v in self.devices.items() if k in live_ids}
        self.edges = {pair for pair in self.edges if all(d in live_ids or d.startswith('external_service:') for d in pair)}
        reset_devices = []
        for device in manifest['inventory']:
            ident = device['device_id']
            identity = digest(dict(device_type=device['device_type'], mac=device.get('mac'),
                                   ips=sorted(a['ip'] for a in device['addresses'])))
            state = self.devices.get(ident)
            if state is None or state['identity'] != identity:
                if state is not None:
                    reset_devices.append(ident)
                    self.edges = {p for p in self.edges if ident not in p}
                state = self.new_device(identity, start)
                self.devices[ident] = state
            available = manifest['capture_complete'] and ident not in unavailable
            values, masks, destinations = features(grouped[ident], state['destinations'])
            extra, extra_masks = extend_features(grouped[ident], manifest, start, state['temporal'], available)
            values += extra
            masks = masks[:18] + extra_masks
            if not available:
                state['past'].clear()
                state['peers'].clear()
                state['prior'].clear()
                state['epoch_start'] = start + 60
            previous = list(state['past'])
            receiver, receiver_masks, peers, count = receiver_features(grouped[ident], state['peers'], state['prior'], start)
            values += receiver
            masks += receiver_masks
            nodes.append(dict(device_id=ident, device_type=device['device_type'], features=values,
                              feature_mask=masks if available else [False] * len(masks),
                              active=bool(grouped[ident]), available=available, temporal_history=previous,
                              label=-1, behavior_label=-1, relationship_label=-1))
            if available:
                state['past'].append(dict(window_start=start, features=[values[FEATURES.index(f)] for f in TEMPORAL_FEATURES],
                                          feature_mask=[masks[FEATURES.index(f)] for f in TEMPORAL_FEATURES],
                                          available=True, active=bool(grouped[ident])))
                state['prior'].append((start, count))
                state['peers'].update(peers)
                state['destinations'].update(destinations)
                require(len(state['peers']) <= self.max_peers and len(state['destinations']) <= self.max_peers and
                        len(state['temporal'].get('streams', {})) <= self.max_peers, 'Per-device peer state limit exceeded')
        index = {n['device_id']: i for i, n in enumerate(nodes)}
        for endpoint in sorted({d for pair in pairs for d in pair if d not in index}):
            index[endpoint] = len(nodes)
            nodes.append(dict(device_id=endpoint, device_type='external_service', service_category=endpoint.split(':', 1)[1],
                              features=[0.] * len(FEATURES), feature_mask=[False] * len(FEATURES), active=False,
                              available=manifest['capture_complete'], temporal_history=[], label=-1, behavior_label=-1, relationship_label=-1))
        edges = []
        for pair, rows in sorted(pairs.items()):
            if not all(nodes[index[d]]['available'] for d in pair):
                continue
            edges.append(dict(source=index[pair[0]], target=index[pair[1]],
                              ip_bytes=sum(r['orig_ip_bytes'] + r['resp_ip_bytes'] for r in rows),
                              packets=sum(r['orig_pkts'] + r['resp_pkts'] for r in rows), flow_count=len(rows),
                              new_edge=pair not in self.edges, protocols=dict(Counter(r['proto'] for r in rows)),
                              ports=sorted({f"{r['proto']}/{r['resp_p']}" for r in rows if r['proto'] in ('tcp', 'udp') and r.get('resp_p') is not None}),
                              confirmed=any(r['established'] or r['proto'] != 'tcp' and r['resp_pkts'] > 0 for r in rows)))
        self.edges.update(pairs)
        self.last_window = start
        graph = dict(schema_version=VERSION, schema_hash=SCHEMA_HASH, run_id=window['run_id'], session_id=window['session_id'],
                     source='live_zeek', normal=False, window_start=start, window_seconds=60, nodes=nodes, edges=edges,
                     observer_age_seconds=start - self.epoch_start,
                     observation_clock=dict(schema_version='automud.observation-clock.v1', mode='live_utc', window_start=start))
        history = {n['device_id']: dict(prior_windows=len(n['temporal_history']),
                   observed_age_seconds=max(0, start - self.devices[n['device_id']]['epoch_start']),
                   fully_warmed=len(n['temporal_history']) == 15 and start - self.devices[n['device_id']]['epoch_start'] >= 3600)
                   for n in nodes if n['device_type'] != 'external_service'}
        if profile is not None:
            from ml.supervised.graphs import project
            graph = project(graph,window['telemetry'],manifest,profile,self.devices,self.model_past)
            for node in graph['nodes']:
                if node['device_type']=='external_service':continue
                count=0
                if node['available']:
                    for previous in reversed(self.model_past):
                        found=[n for n in previous['nodes'] if n['device_id']==node['device_id']]
                        if previous['window_start']!=start-60*(count+1) or len(found)!=1 or not found[0]['available'] or found[0].get('identity_epoch')!=node.get('identity_epoch'):break
                        count+=1
                history[node['device_id']]['prior_windows']=count
                history[node['device_id']]['fully_warmed']=count==15 and history[node['device_id']]['observed_age_seconds']>=3600
            saved={k:v for k,v in graph.items() if k!='prior_graphs'}
            saved=copy_graph(saved)
            for node in saved['nodes']: node.pop('temporal_history',None)
            self.model_past.append(copy_graph(saved))
        return graph, dict(epoch=self.epoch, reset_reason=reason, reset_device_ids=reset_devices,
                           model_history_reset_reason=model_reset, history=history)

    def dump(self):
        devices = {}
        for ident, state in self.devices.items():
            temporal = state['temporal']
            devices[ident] = dict(identity=state['identity'], epoch_start=state['epoch_start'],
                destinations=sorted(state['destinations']), peers=sorted(state['peers']), prior=list(state['prior']), past=list(state['past']),
                temporal=dict(windows=list(temporal.get('windows', [])), starts=list(temporal.get('starts', [])),
                              streams=[[list(k), list(v)] for k, v in temporal.get('streams', {}).items()]))
            devices[ident]['flow']={'history':list(state.get('flow',{}).get('history',[]))}
        return dict(devices=devices, edges=[list(p) for p in sorted(self.edges)], last_window=self.last_window,
                    model_past=list(self.model_past), model_profile_id=self.model_profile_id,
                    epoch_start=self.epoch_start, epoch=self.epoch, max_peers=self.max_peers)

    @classmethod
    def restore(cls, value):
        builder = cls(value['max_peers'])
        builder.edges = {tuple(p) for p in value['edges']}
        builder.last_window, builder.epoch_start, builder.epoch = value['last_window'], value['epoch_start'], value['epoch']
        builder.model_past=deque(value.get('model_past',[]),maxlen=15)
        builder.model_profile_id=value.get('model_profile_id')
        for ident, saved in value['devices'].items():
            builder.devices[ident] = dict(saved, destinations=set(saved['destinations']), peers=set(saved['peers']),
                prior=deque(saved['prior'], maxlen=5), past=deque(saved['past'], maxlen=15),
                temporal=dict(windows=deque(saved['temporal']['windows']), starts=deque(saved['temporal']['starts']),
                              streams={tuple(k): deque(v) for k, v in saved['temporal']['streams']}))
            builder.devices[ident]['flow']={'history':deque(saved.get('flow',{}).get('history',[]),maxlen=60)}
        return builder

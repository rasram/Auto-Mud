"""Receiver features and packet-backed labels, without mutating historical captures."""
import math
from collections import defaultdict, deque
from ml.schema import require, resolve_device, validate_telemetry
from ml.graph.build import build_snapshots
from ml.ab_targets.schema import FEATURES, TEMPORAL_FEATURES, VERSION, SCHEMA_HASH


def receiver_features(records, seen_peers, prior, start):
    inbound = [r for r, orig in records if not orig]
    starts = [r for r in inbound if r['new_flow']]
    peers = {r['orig_h'] for r in inbound}
    ports = {(r['proto'], r['resp_p']) for r in inbound if r['proto'] in ('tcp','udp') and r.get('resp_p') is not None}
    outcomes = [r for r in inbound if r['proto']=='tcp' and (r['failed'] or r['established'])]
    recent = [n for timestamp,n in prior if start-300<=timestamp<start]
    values = [len(peers), len(peers-seen_peers)/len(peers) if peers else 0., len(ports),
              sum(bool(r['failed']) for r in outcomes)/len(outcomes) if outcomes else 0.,
              len(inbound)/len(records) if records else 0.,
              math.log1p(len(starts))-math.log1p(sum(recent)/len(recent)) if recent else 0.]
    return values, [True,bool(peers),True,bool(outcomes),bool(records),bool(recent)], peers, len(starts)


def observed_labels(plan, manifest, rows):
    """Match authored malicious events to accepted Zeek flows by visible tuple/time.

    Actor compromise stays unchanged. Unobserved planned behavior is unknown,
    not a benign negative. No model score participates in this label audit.
    """
    if not plan or not plan.get('scenario') or plan.get('normal_control'):
        return {}, dict(planned=0, observed=0, passed=True)
    families = ('port_scan','lateral_connections','exfiltration','beaconing')
    ip_device = {ip:d for d,ip in plan['topology']['device_ip'].items()}
    indexed = defaultdict(list)
    for row in rows:
        indexed[(row['orig_h'],row['resp_h'],row['proto'],row.get('resp_p'))].append(row)
    planned = defaultdict(set); observed = defaultdict(set); total = matched = 0
    for event in plan['events']:
        if event.get('kind') not in families: continue
        total += 1
        timestamp = manifest['start']+event['offset']
        minute = int(timestamp//60)*60
        actor = event['device_id']; target = ip_device.get(event['destination'])
        key = (plan['topology']['device_ip'][actor],event['destination'],event['proto'],event['port'])
        found = any(r['orig_pkts']>0 and abs(r['flow_start']-timestamp)<=.05 for r in indexed[key])
        planned[actor].add(minute)
        if target: planned[target].add(minute)
        if found:
            matched += 1; observed[actor].add(minute)
            if target: observed[target].add(minute)
    targets = {}
    for device, minutes in planned.items():
        for minute in minutes:
            value = 1 if minute in observed[device] else -1
            targets[(device,minute)] = dict(behavior_label=value,
                relationship_label=value if device==plan['actor'] and plan['scenario'] in ('port_scan','lateral_connections') else 0,
                affected_role='actor' if device==plan['actor'] else 'victim')
    # Compromised actor windows with no captured/planned event are explicitly unknown.
    for minute in range(manifest['start']+plan['attack_start'],manifest['end'],60):
        targets.setdefault((plan['actor'],minute), dict(behavior_label=-1,
            relationship_label=-1 if plan['scenario'] in ('port_scan','lateral_connections') else 0, affected_role='actor'))
    return targets, dict(planned=total, observed=matched, observed_fraction=matched/total if total else None,
                         passed=bool(total) and matched/total>=.99)


def build_v4(telemetry, manifest, labels=(), plan=None):
    rows = list(telemetry)
    for row in rows: validate_telemetry(row)
    targets, audit = observed_labels(plan,manifest,rows)
    require(audit['passed'], 'Less than 99% of planned malicious events have accepted packet evidence')
    grouped = defaultdict(lambda:defaultdict(list))
    for row in rows:
        for side,orig in (('orig',True),('resp',False)):
            device = resolve_device(manifest,row[side+'_h'],row.get(side+'_mac'),row['window_start'])
            if device: grouped[row['window_start']][device].append((row,orig))
    peers = defaultdict(set); prior = defaultdict(lambda:deque(maxlen=5))
    history = defaultdict(lambda:deque(maxlen=15))
    for graph in build_snapshots(iter(rows),manifest,labels):
        graph.update(schema_version=VERSION,schema_hash=SCHEMA_HASH,label_audit=audit,
            attack_family=plan.get('scenario') if plan else None,
            onset=plan.get('onset','normal') if plan and plan.get('scenario') else 'normal',
            challenge='ambiguous_beacon' if plan and plan.get('scenario')=='beaconing' else None,
            observer_age_seconds=graph['window_start']-manifest['start'])
        for node in graph['nodes']:
            device = node['device_id']; start = graph['window_start']
            if node['device_type']=='external_service':
                node['features'] += [0.]*6; node['feature_mask'] += [False]*6
                node['temporal_history'] = []; continue
            if not node['available']:
                history[device].clear(); peers[device].clear(); prior[device].clear()
            values, masks, current, count = receiver_features(grouped[start][device],peers[device],prior[device],start)
            node['features'] += values
            node['feature_mask'] += masks if node['available'] else [False]*6
            node['temporal_history'] = list(history[device])
            if node['available']:
                history[device].append(dict(window_start=start,
                    features=[node['features'][FEATURES.index(f)] for f in TEMPORAL_FEATURES],
                    feature_mask=[node['feature_mask'][FEATURES.index(f)] for f in TEMPORAL_FEATURES],
                    available=True,active=node['active']))
                prior[device].append((start,count)); peers[device].update(current)
            if (device,start) in targets and node['available']: node.update(targets[(device,start)])
        yield graph

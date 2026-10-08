"""Causal context from measured flow intervals; no scenario names or labels."""
from collections import Counter, deque
import math
import statistics

from ml.schema import service_category, resolve_device


def service_id(row):
    return 'external_service:' + service_category(row['proto'], row.get('resp_p'))


def extend_features(records, manifest, start, state, available):
    history, starts = state.setdefault('windows', deque()), state.setdefault('starts', deque())
    if not available:
        history.clear(); starts.clear()
        return [0.] * 20, [False] * 20
    while history and history[0][0] < start - 900: history.popleft()
    while starts and starts[0] < start - 900: starts.popleft()
    local_tx = external_tx = local_rx = external_rx = external = initiated = tx = 0
    services, new = Counter(), []
    for r, originator in records:
        remote = resolve_device(manifest, r['resp_h'] if originator else r['orig_h'],
                                r.get('resp_mac' if originator else 'orig_mac'), start)
        sent, received = ('orig', 'resp') if originator else ('resp', 'orig')
        tb, rb = r[sent+'_ip_bytes'], r[received+'_ip_bytes']
        tx += tb
        if remote:
            local_tx += tb; local_rx += rb
        else:
            external_tx += tb; external_rx += rb; external += 1
        services[service_category(r['proto'], r.get('resp_p'))] += 1
        if originator and r['new_flow']:
            initiated += 1; new.append(r['flow_start'])
    current = sorted(new)
    # The last previous connection is included to measure gaps across window boundaries.
    sequence = ([starts[-1]] if starts else []) + current
    gaps = [b-a for a,b in zip(sequence,sequence[1:]) if b>a]
    mean_gap = statistics.mean(gaps) if gaps else 0.
    cv = statistics.pstdev(gaps)/mean_gap if len(gaps)>1 and mean_gap else 0.
    all_starts = sorted([*starts, *current])
    rolling_gaps = [b-a for a,b in zip(all_starts,all_starts[1:]) if b>a]
    rolling_cv = statistics.pstdev(rolling_gaps)/statistics.mean(rolling_gaps) if len(rolling_gaps)>1 else 0.
    recent = [r for r in history if r[0]>=start-300]
    mean5 = statistics.mean(r[1] for r in recent) if recent else 0.
    mean15 = statistics.mean(r[1] for r in history) if history else 0.
    n = len(records)
    values = [local_tx,external_tx,local_rx,external_rx,external/n if n else 0.,
              *(services[s]/n if n else 0. for s in ('web','tls','dns')),
              (services['other_tcp']+services['other_udp'])/n if n else 0.,
              tx/initiated if initiated else 0.,mean_gap,cv,min(gaps) if gaps else 0.,
              max(Counter(int((t-start)//10) for t in current).values(),default=0),
              mean5,mean15,statistics.mean(r[2] for r in recent) if recent else 0.,
              math.log1p(tx)-math.log1p(mean5) if recent else 0.,
              math.log1p(tx)-math.log1p(mean15) if history else 0.,rolling_cv]
    mask = [True]*20
    for i in range(4,9): mask[i]=bool(n)
    mask[9]=bool(initiated)
    mask[10]=mask[12]=bool(gaps); mask[11]=len(gaps)>1
    mask[14]=mask[16]=mask[17]=bool(recent)
    mask[15]=mask[18]=bool(history); mask[19]=len(rolling_gaps)>1
    history.append((start,tx,n)); starts.extend(current)
    return values,mask


def target_label(labels, device, start, name, fallback):
    matching = [r for r in labels if r['device_id']==device and r['start']<=start and r['end']>=start+60]
    if not matching: return fallback
    intervals = [i for r in matching for i in r.get(name+'_intervals',[])]
    if intervals:
        full = [i for i in intervals if i['start']<=start and i['end']>=start+60]
        partial = [i for i in intervals if i['start']<start+60 and i['end']>start]
        return 1 if full else -1 if partial else 0
    explicit = {r.get(name+'_label', fallback) for r in matching}
    return explicit.pop() if len(explicit)==1 else -1

"""Profiles and past-only directed flow context; no payload, class or numeric IDs."""
from collections import Counter,defaultdict,deque
import json
import math
import numpy as np
from ml.schema import resolve_device,require
def grouped(rows,manifest):
    groups=defaultdict(list)
    for r in rows:
        for side,orig in (('orig',True),('resp',False)):
            device=resolve_device(manifest,r[side+'_h'],r.get(side+'_mac'),r['window_start'])
            if device:groups[(r['window_start'],device)].append((r,orig))
    return groups


def key(row,orig,manifest):
    side='resp' if orig else 'orig'
    peer=resolve_device(manifest,row[side+'_h'],row.get(side+'_mac'),row['window_start']) or row[side+'_h']
    return json.dumps((peer,row['proto'],row.get('resp_p')),separators=(',',':'))


def features(records,manifest,device,start,state,profile):
    incoming=[(r,o) for r,o in records if not o];outgoing=[(r,o) for r,o in records if o]
    values=[];masks=[]
    for rarity in (False,True):
        for direction,items in (('in',incoming),('out',outgoing)):
            ref=profile['groups'].get(device+'|'+direction)
            keys=[key(r,o,manifest) for r,o in items]
            known=ref is not None and ref['total']>0
            if keys and known:
                if rarity:
                    denom=ref['total']+len(ref['counts'])+1
                    value=sum(-math.log((ref['counts'].get(k,0)+1)/denom) for k in keys)/len(keys)
                else:value=sum(k not in ref['counts'] for k in keys)/len(keys)
            else:value=0.
            values.append(value);masks.append(bool(keys) and known)
    history=state.setdefault('history',deque(maxlen=60))
    recent=[row for row in history if start-900<=row[0]<start]
    tx=sum(r['orig_ip_bytes'] for r,o in outgoing if not resolve_device(manifest,r['resp_h'],r.get('resp_mac'),start))
    inc=sum(r['new_flow'] for r,o in incoming)
    keys=[key(r,o,manifest) for r,o in incoming]
    mean_tx=float(np.mean([r[1] for r in recent])) if recent else 0.
    mean_in=float(np.mean([r[2] for r in recent])) if recent else 0.
    recent_in=[k for row in history if start-300<=row[0]<start for k in row[3]]
    concentration=max(Counter(recent_in).values(),default=0)/len(recent_in) if recent_in else 0.
    # Sustain is the entire preceding fifteen-minute average against the frozen
    # clean prefix, not another current-minute change feature.
    baseline=profile.get('external_tx_baseline_by_device',{}).get(device)
    complete=len(recent)==15 and [r[0] for r in recent]==list(range(start-900,start,60))
    sustained=math.log1p(mean_tx)-math.log1p(baseline) if complete and baseline is not None else 0.
    values.extend((sustained,math.log1p(inc)-math.log1p(mean_in),concentration))
    masks.extend((complete and baseline is not None,bool(recent),bool(recent_in)))
    history.append((start,tx,inc,keys))
    return values,masks

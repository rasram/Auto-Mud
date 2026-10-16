"""Profile/history projection shared by streaming and offline deployment inputs."""
import copy
import hashlib
import json
from ml.schema import require
from ml.supervised.profile_features import grouped,features
from ml.supervised.tensors import v6


def profile_id(profile):
    return hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest()


def project(graph,rows,manifest,profile,states,prior):
    lookup=grouped(rows,manifest)
    result=copy.deepcopy(graph)
    for node in result['nodes']:
        ident=node['device_id']
        if node['device_type']=='external_service':
            extra,mask=[0.]*7,[False]*7
        else:
            state=states[ident]
            node['identity_epoch']=state['identity']
            if not node['available']:
                state['flow']={}
                extra,mask=[0.]*7,[False]*7
            else:
                extra,mask=features(lookup[(graph['window_start'],ident)],manifest,ident,
                    graph['window_start'],state.setdefault('flow',{}),profile)
        node['features']+=extra;node['feature_mask']+=mask
    result=v6(result,profile)
    result['flow_profile_sha256']=profile_id(profile)
    result['prior_graphs']=copy.deepcopy(list(prior))
    return result


def build_graphs(rows,manifest,profile):
    """Build observed UTC deployment inputs; includes explicit unhealthy minutes."""
    from ml.live.graphs import StreamingGraph
    from ml.live.contracts import validate_window
    from ml.schema import validate_manifest
    validate_manifest(manifest)
    rows=list(rows);by_time={}
    for row in rows:by_time.setdefault(row['window_start'],[]).append(row)
    builder=StreamingGraph()
    for start in range(manifest['start'],manifest['end'],60):
        outages=[v for v in manifest.get('outages',[]) if v['start']<start+60 and v['end']>start]
        window=dict(schema_version='automud.live-window.v1',observation_kind='live',
            run_id=manifest['run_id'],session_id=manifest['session_id'],sensor_id='offline-extraction',
            inventory_version='manifest-inventory',window_start=start,window_end=start+60,watermark=start+60,
            inventory=manifest['inventory'],telemetry=by_time.get(start,[]),
            health=dict(complete=manifest['capture_complete'] and not any(not v.get('device_id') for v in outages),
                sensor_healthy=True,clock_synchronized=True,capture_drops=manifest.get('capture_drops',0),
                unavailable_device_ids=sorted({v['device_id'] for v in outages if v.get('device_id')})))
        window=validate_window(window,now=manifest['end'])
        graph,_=builder.build(window,profile=profile)
        yield graph

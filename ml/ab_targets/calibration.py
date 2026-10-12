"""Lookup of saved clean thresholds; no threshold fitting."""
def observable_context(graph,index):
    outgoing=[graph['nodes'][e['target']] for e in graph['edges'] if e['source']==index]
    external=sorted({n.get('service_category','unknown') for n in outgoing if n['device_type']=='external_service'})
    local=any(n['device_type']!='external_service' for n in outgoing)
    return ('local+' if local else '')+('+'.join(external) if external else 'local' if local else 'none')



def context(graph,index):
    age=graph.get('observer_age_seconds',0)//60
    band='0-2' if age<3 else '3-5' if age<6 else '6-19'
    return observable_context(graph,index)+'|age='+band



def threshold_info(thresholds,node,observable):
    for key in ('context:'+node['device_id']+'|'+observable,'device:'+node['device_id'],'type:'+node['device_type']):
        if key in thresholds['groups']: return dict(thresholds['groups'][key],scope=key,fallback=False)
    return dict(thresholds['global_threshold'],scope='global',fallback=True)


"""Native captured-source clocks and real live UTC share the saved encoder."""
import math
from ml.schema import require


def native_offsets(graph):
    start = graph['window_start']
    live = graph.get('observation_clock')
    if live is not None:
        require(live == dict(schema_version='automud.observation-clock.v1', mode='live_utc',
                            window_start=start), 'Invalid live observation clock')
        require(isinstance(start, int) and start >= 0 and start % 60 == 0, 'Invalid UTC minute')
        return {n['device_id']: 0 for n in graph['nodes']}
    intervals = {}
    for entry in (graph.get('source_interval_id') or '').split('|'):
        if entry:
            device, _, lo, hi = entry.rsplit(':', 3)
            require(device not in intervals, 'Repeated native source identity')
            intervals[device] = int(lo), int(hi)
    age = graph.get('observer_age_seconds')
    require(isinstance(age, (int, float)) and not isinstance(age, bool) and math.isfinite(age) and age >= 0,
            'Native clock unavailable')
    result = {}
    for node in graph['nodes']:
        if node['device_type'] == 'external_service':
            result[node['device_id']] = 0
        else:
            require(node['device_id'] in intervals, 'Native clock unavailable')
            lo, hi = intervals[node['device_id']]
            require(lo + age < hi, 'Native clock outside source interval')
            result[node['device_id']] = lo + age - start
    return result

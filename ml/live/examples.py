"""Explicit engineering examples, never training/accuracy evidence."""
def example_window(start, run_id='engineering-demo', session_id='demo-1'):
    return dict(schema_version='automud.live-window.v1', observation_kind='engineering', run_id=run_id, session_id=session_id,
        sensor_id='zeek-1', inventory_version='inventory-1', window_start=start, window_end=start+60, watermark=start+60,
        inventory=[dict(device_id='demo-camera', device_type='camera', addresses=[dict(ip='10.0.0.11', start=start, end=None)]),
                   dict(device_id='demo-hub', device_type='hub', addresses=[dict(ip='10.0.0.12', start=start, end=None)])],
        health=dict(complete=True, sensor_healthy=True, clock_synchronized=True, capture_drops=0, unavailable_device_ids=[]),
        telemetry=[dict(schema_version='automud.graph.v1', window_start=start, uid='demo-flow-'+str(start),
                       orig_h='10.0.0.11', resp_h='10.0.0.12', orig_p=40000, resp_p=8080, proto='tcp', flow_start=start+1,
                       orig_ip_bytes=100, resp_ip_bytes=120, orig_pkts=2, resp_pkts=2, observed_duration=2.,
                       established=True, failed=False, new_flow=True, tcp_syn_observed=True)])

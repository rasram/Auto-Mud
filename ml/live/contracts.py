"""Public external contracts; model features and training metadata stay internal."""
import copy
import hashlib
import ipaddress
import json
import time
from pathlib import Path
from jsonschema import Draft202012Validator
from ml.schema import TYPES, validate_telemetry, require

INPUT_VERSION = 'automud.live-window.v1'
ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / 'configs/gnn/live/window.schema.json'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def validate_window(value, now=None, future_skew_seconds=2):
    errors = sorted(Draft202012Validator(json.loads(SCHEMA_PATH.read_text())).iter_errors(value), key=lambda e: str(e.path))
    require(not errors, 'Window schema: ' + (errors[0].message if errors else ''))
    window = copy.deepcopy(value)
    window['window_start'], window['window_end'] = int(window['window_start']), int(window['window_end'])
    start, end = window['window_start'], window['window_end']
    require(end == start + 60, 'Expected one 60-second window')
    require(end <= (time.time() if now is None else now) + future_skew_seconds, 'Window is not yet closed')
    require(window['watermark'] >= end or not window['health']['complete'], 'Completed window lacks closing watermark')
    ids = [d['device_id'] for d in window['inventory']]
    require(len(ids) == len(set(ids)), 'Duplicate device identity')
    require(set(window['health']['unavailable_device_ids']) <= set(ids), 'Unavailable identity absent from inventory')
    macs = set()
    owners = {}
    for device in window['inventory']:
        require(device['device_type'] in TYPES and device['device_type'] != 'external_service', 'Invalid household device type')
        mac = device.get('mac', '').lower()
        if mac:
            device['mac'] = mac
        require(not mac or mac not in macs, 'Duplicate device MAC')
        if mac:
            macs.add(mac)
        for address in device['addresses']:
            ipaddress.ip_address(address['ip'])
            address['ip'] = str(ipaddress.ip_address(address['ip']))
            lo, hi = address['start'], address['end']
            require(hi is None or hi > lo, 'Invalid address lease')
            if lo < end and (hi is None or hi > start):
                # Ownership changes inside a minute are marked unscored below;
                # simultaneous ownership at any observed time is a hard error.
                interval = (max(lo, start), min(hi, end) if hi is not None else end)
                for other, other_interval in owners.get(address['ip'], []):
                    require(other == device['device_id'] or interval[0] >= other_interval[1] or other_interval[0] >= interval[1],
                            'Ambiguous IP ownership: ' + address['ip'])
                owners.setdefault(address['ip'], []).append((device['device_id'], interval))
    seen = set()
    for row in window['telemetry']:
        validate_telemetry(row)
        row['orig_h'], row['resp_h'] = str(ipaddress.ip_address(row['orig_h'])), str(ipaddress.ip_address(row['resp_h']))
        require(row['window_start'] == start, 'Telemetry belongs to another window')
        require(row['uid'] not in seen, 'Duplicate flow interval UID')
        seen.add(row['uid'])
    window['telemetry'].sort(key=lambda r: r['uid'])
    window['inventory'].sort(key=lambda d: d['device_id'])
    for device in window['inventory']:
        device['addresses'].sort(key=lambda a: (a['ip'], a['start']))
    window['health']['unavailable_device_ids'].sort()
    return window


def observed_manifest(window):
    start, end = window['window_start'], window['window_end']
    inventory = []
    unavailable = set(window['health']['unavailable_device_ids'])
    for device in window['inventory']:
        active = []
        for a in device['addresses']:
            if a['start'] < end and (a['end'] is None or a['end'] > start):
                if start < a['start'] < end or a['end'] is not None and start < a['end'] < end:
                    unavailable.add(device['device_id'])
                active.append(dict(ip=a['ip'], start=max(a['start'], start),
                                   end=min(a['end'], end) if a['end'] is not None else end))
        if not active:
            unavailable.add(device['device_id'])
        inventory.append(dict(device, addresses=active))
    health = window['health']
    healthy = health['complete'] and health['sensor_healthy'] and health['clock_synchronized'] and health['capture_drops'] == 0
    return dict(schema_version='automud.graph.v3', run_id=window['run_id'], session_id=window['session_id'],
                source='live_zeek', start=start, end=end, normal=False, capture_complete=healthy,
                replay_speed=1, inventory=inventory), unavailable

"""Runtime sequence resampling used by the shared Mininet generator."""
from collections import defaultdict
from ml.schema import require

def sequence_events(device, profile, profiles, duration, rng, cloud_ips, local_ip=None):
    """Resample contiguous measured blocks; preserve peers and TCP UID across intervals."""
    result=[]; block_seconds=profiles['block_seconds']
    for base in range(0,duration,block_seconds):
        block=rng.choice(profile['blocks'])
        groups=defaultdict(list)
        for r in block['events']:
            if base+r['offset'] >= duration: continue
            groups[r['uid']].append(r)
        for uid,rows in groups.items():
            first=rows[0]; offset=base+first['offset']
            segments=[]
            for r in rows:
                # Split large transfers rather than clipping volume. Keep one TCP connection.
                count=max(1,(max(r['request_bytes'],r['response_bytes'])+65535)//65536)
                require(count<=4096, "Reference interval exceeds safe segment bound")
                tx,rx=r['request_bytes'],r['response_bytes']
                for i in range(count):
                    at=base+r['offset']+i*min(r['duration'],59)/count
                    if at>=duration: break
                    segments.append({'offset':at-offset,'request_bytes':min(65536,tx),
                                     'response_bytes':min(65536,rx),'duration':min(r['duration']/count,duration-at)})
                    tx-=min(65536,tx);rx-=min(65536,rx)
            if not segments: continue
            event={'device_id':device,'offset':offset,'destination':cloud_ips[first['peer_slot']],
                   'proto':first['proto'],'port':first['port'],'kind':'normal_measured',
                   'request_bytes':segments[0]['request_bytes'],'response_bytes':segments[0]['response_bytes'],
                   'duration':segments[-1]['offset']+segments[-1]['duration'],
                   'segments':segments,'expect_failure':bool(first['failed']),
                   'reference_block_start':block['reference_start'],'reference_uid':uid,
                   'activity_state':block['state']}
            if not first.get('originator',True):
                require(local_ip,'Incoming measured traffic needs a local device address')
                event.update(device_id='cloud-'+str(first['peer_slot']),destination=local_ip,
                             source_ip=cloud_ips[first['peer_slot']],target_device_id=device)
            result.append(event)
    return result

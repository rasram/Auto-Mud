# Canonical 60-second IP telemetry for AutoMUD. Run this policy both offline
# and live. new_packet gives exact interval allocation, including long flows.
# This intentionally favors correctness at household scale over sensor throughput.
@load base/protocols/conn
@load policy/protocols/conn/mac-logging
@load policy/tuning/json-logs

module AutoMUD;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        schema_version: string &log &default="automud.graph.v1";
        window_start: double &log;
        uid: string &log;
        orig_h: addr &log;
        resp_h: addr &log;
        orig_p: count &log;
        resp_p: count &log;
        proto: string &log;
        flow_start: double &log;
        orig_ip_bytes: count &log &default=0;
        resp_ip_bytes: count &log &default=0;
        orig_pkts: count &log &default=0;
        resp_pkts: count &log &default=0;
        observed_duration: double &log &default=0.0;
        established: bool &log &default=F;
        failed: bool &log &default=F;
        new_flow: bool &log &default=F;
        orig_mac: string &log &optional;
        resp_mac: string &log &optional;
    };
}

global rows: table[string] of Info;
global current_window: double = -1.0;
global established_uids: table[string] of double;
global rejected_uids: table[string] of double;
global pending_cleanup: set[string];

function flush_window()
    {
    for (uid in rows)
        {
        local r = rows[uid];
        r$established = uid in established_uids && established_uids[uid] < current_window + 60.0;
        # A reset after establishment is not a failed handshake. Three seconds
        # without establishment is an observable timeout, not future conn.log state.
        r$failed = r$proto == "tcp" && ! r$established &&
                    ((uid in rejected_uids && rejected_uids[uid] < current_window + 60.0) || current_window + 60.0 - r$flow_start >= 3.0);
        Log::write(LOG, r);
        }
    rows = table();
    for (uid in pending_cleanup)
        {
        delete established_uids[uid];
        delete rejected_uids[uid];
        }
    pending_cleanup = set();
    }

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="automud-window"]);
    }

event connection_established(c: connection)
    {
    established_uids[c$uid] = time_to_double(network_time());
    }

event connection_rejected(c: connection)
    {
    rejected_uids[c$uid] = time_to_double(network_time());
    }

event connection_state_remove(c: connection)
    {
    if ( c$uid in rows )
        add pending_cleanup[c$uid];
    else
        {
        delete established_uids[c$uid];
        delete rejected_uids[c$uid];
        }
    }

event interval_tick()
    {
    local next_window = floor(time_to_double(network_time()) / 60.0) * 60.0;
    if ( current_window >= 0.0 && next_window > current_window )
        {
        flush_window();
        current_window = next_window;
        }
    schedule 1sec { interval_tick() };
    }

event zeek_init() &priority=-5
    {
    schedule 1sec { interval_tick() };
    }

event new_packet(c: connection, p: pkt_hdr)
    {
    local ts = time_to_double(network_time());
    local window = floor(ts / 60.0) * 60.0;
    if ( current_window < 0.0 ) current_window = window;
    if ( window > current_window )
        {
        flush_window();
        current_window = window;
        }
    if ( window < current_window )
        {
        Reporter::warning("AutoMUD out-of-order packet crossed an emitted window");
        return;
        }
    if ( c$uid !in rows )
        {
        local r: Info = [$window_start=window, $uid=c$uid,
                         $orig_h=c$id$orig_h, $resp_h=c$id$resp_h,
                         $orig_p=port_to_count(c$id$orig_p), $resp_p=port_to_count(c$id$resp_p),
                         $proto=fmt("%s", get_port_transport_proto(c$id$orig_p)),
                         $flow_start=time_to_double(c$start_time),
                         $new_flow=time_to_double(c$start_time) >= window];
        if ( c$orig?$l2_addr ) r$orig_mac = c$orig$l2_addr;
        if ( c$resp?$l2_addr ) r$resp_mac = c$resp$l2_addr;
        rows[c$uid] = r;
        }
    local orig = T;
    local bytes: count = 0;
    if ( p?$ip )
        {
        orig = p$ip$src == rows[c$uid]$orig_h;
        bytes = p$ip$len;
        }
    else if ( p?$ip6 )
        {
        orig = p$ip6$src == rows[c$uid]$orig_h;
        bytes = 40 + p$ip6$len;
        }
    else return;
    if ( orig )
        {
        rows[c$uid]$orig_ip_bytes += bytes;
        ++rows[c$uid]$orig_pkts;
        }
    else
        {
        rows[c$uid]$resp_ip_bytes += bytes;
        ++rows[c$uid]$resp_pkts;
        }
    rows[c$uid]$observed_duration = ts - rows[c$uid]$flow_start;
    }

event zeek_done()
    {
    flush_window();
    }

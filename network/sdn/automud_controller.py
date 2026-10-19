"""OpenFlow 1.3 learning switch and idempotent, expiring AutoMUD actions.

Run with OS-Ken (the maintained Ryu fork on Ubuntu 24.04):
    osken-manager network/sdn/automud_controller.py
"""
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from os_ken.lib import hub
    from os_ken.lib.packet import ethernet, packet
    from os_ken.ofproto import ofproto_v1_3
except ImportError:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.lib import hub
    from ryu.lib.packet import ethernet, packet
    from ryu.ofproto import ofproto_v1_3

COOKIE_PREFIX = 0xA17D000000000000
COOKIE_MASK = 0xFFFF000000000000


def _cookie(decision_id):
    return COOKIE_PREFIX | int(hashlib.sha256(decision_id.encode()).hexdigest()[:12], 16)


ControllerApp = getattr(app_manager, "RyuApp", None) or app_manager.OSKenApp


class AutoMUDController(ControllerApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.actions = {}
        self.pending_barriers = {}
        self.lock = threading.RLock()
        self.allow_engineering_actions = os.environ.get(
            "AUTOMUD_CONTROLLER_ALLOW_ENGINEERING_ACTIONS", "false"
        ).lower() in ("1", "true", "yes")
        self.maximum_ttl = int(os.environ.get("AUTOMUD_CONTROLLER_MAX_TTL_SECONDS", "300"))
        handler = type("AutoMUDActionHandler", (_ActionHandler,), {"app": self})
        api_port = int(os.environ.get("AUTOMUD_CONTROLLER_API_PORT", "8080"))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", api_port), handler)
        self.http_thread = threading.Thread(target=self.httpd.serve_forever, name="automud-action-api", daemon=True)
        self.http_thread.start()
        self.logger.info("AutoMUD action API listening on 127.0.0.1:%d", api_port)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().close()

    def add_flow(self, datapath, priority, match, actions, cookie=0, hard_timeout=0, send_removed=False):
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        flags = ofp.OFPFF_SEND_FLOW_REM if send_removed else 0
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=instructions, cookie=cookie, hard_timeout=hard_timeout, flags=flags,
        ))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, event):
        datapath = event.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, cookie=COOKIE_PREFIX, cookie_mask=COOKIE_MASK,
            table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
        ))
        self.add_flow(datapath, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self.logger.info("AutoMUD switch connected dpid=%016x", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnected(self, event):
        dpid = event.datapath.id
        self.datapaths.pop(dpid, None)
        self.mac_to_port.pop(dpid, None)
        self.logger.info("AutoMUD switch disconnected dpid=%016x", dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, event):
        msg, datapath = event.msg, event.msg.datapath
        parser, ofp, dpid = datapath.ofproto_parser, datapath.ofproto, datapath.id
        in_port = msg.match["in_port"]
        parsed = packet.Packet(msg.data)
        eth = parsed.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        self.mac_to_port.setdefault(dpid, {})[eth.src.lower()] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst.lower(), ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            self.add_flow(datapath, 10, parser.OFPMatch(in_port=in_port, eth_dst=eth.dst), actions)
        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data,
        ))

    def install_action(self, value):
        required = {
            "schema_version", "decision_id", "proposal_id", "dpid", "device_id", "device_mac",
            "device_ip", "switch_port", "action", "scope", "priority", "ttl_seconds", "reason",
            "evidence_id", "observation_kind", "inventory_version", "window_end",
        }
        missing = required - set(value)
        if missing:
            raise ValueError("Missing action fields: " + ", ".join(sorted(missing)))
        if value["schema_version"] != "automud.action-request.v1" or value["action"] != "block":
            raise ValueError("Only automud.action-request.v1 temporary block actions are supported")
        if value["observation_kind"] not in ("live", "engineering"):
            raise ValueError("Unknown observation kind")
        if value["observation_kind"] != "live" and not self.allow_engineering_actions:
            raise ValueError("Engineering actions are disabled by controller policy")
        ttl = int(value["ttl_seconds"])
        priority = int(value["priority"])
        if not 1 <= ttl <= self.maximum_ttl or not 1000 <= priority <= 60000:
            raise ValueError("Unsafe action TTL or priority")
        if time.time() - float(value["window_end"]) > 180:
            raise ValueError("Action observation is stale")
        if not re.fullmatch(r"[0-9a-fA-F]{16}", str(value["dpid"])):
            raise ValueError("Invalid DPID")
        mac = str(value["device_mac"]).lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise ValueError("Invalid device MAC")
        if str(ipaddress.ip_address(value["device_ip"])) != value["device_ip"]:
            raise ValueError("Invalid device IP")
        scope = value.get("scope")
        if not isinstance(scope, dict) or not scope.get("destination_ip") or scope.get("proto") not in ("tcp", "udp"):
            raise ValueError("Block action requires a narrow destination/protocol scope")
        ipaddress.ip_address(scope["destination_ip"])
        if scope.get("destination_port") is None or not 1 <= int(scope["destination_port"]) <= 65535:
            raise ValueError("Block action requires a valid destination port")
        decision_id = value["decision_id"]
        with self.lock:
            previous = self.actions.get(decision_id)
            if previous:
                if previous["request"] != value:
                    raise ValueError("Conflicting duplicate decision_id")
                return previous.copy()
            dpid = int(str(value["dpid"]), 16)
            datapath = self.datapaths.get(dpid)
            if datapath is None:
                raise ValueError("Requested switch is not connected")
            learned = self.mac_to_port.get(dpid, {}).get(mac)
            port = int(value["switch_port"])
            if learned is None:
                raise ValueError("Device binding is not learned by the controller")
            if learned != port:
                raise ValueError(f"Stale device binding: expected port {port}, current port {learned}")
            parser = datapath.ofproto_parser
            match_fields = {"in_port": port, "eth_src": mac, "eth_type": 0x0800, "ipv4_src": value["device_ip"]}
            if scope.get("destination_ip"):
                match_fields["ipv4_dst"] = scope["destination_ip"]
            protocol = scope.get("proto")
            if protocol in ("tcp", "udp"):
                match_fields["ip_proto"] = 6 if protocol == "tcp" else 17
                if scope.get("destination_port") is not None:
                    match_fields["tcp_dst" if protocol == "tcp" else "udp_dst"] = int(scope["destination_port"])
            cookie = _cookie(decision_id)
            self.add_flow(datapath, priority, parser.OFPMatch(**match_fields), [], cookie=cookie, hard_timeout=ttl, send_removed=True)
            barrier = parser.OFPBarrierRequest(datapath)
            datapath.set_xid(barrier)
            self.pending_barriers[(dpid, barrier.xid)] = (decision_id, "install")
            datapath.send_msg(barrier)
            accepted_at = time.time()
            record = {
                "schema_version": "automud.action-result.v1", "decision_id": decision_id,
                "status": "accepted", "request": value, "cookie": f"0x{cookie:016x}",
                "accepted_at": accepted_at, "installed_at": None, "expires_at": accepted_at + ttl,
                "error": None,
            }
            self.actions[decision_id] = record
            hub.spawn_after(ttl + 1, self._mark_expired, decision_id)
            return record.copy()

    def revoke_action(self, decision_id):
        with self.lock:
            record = self.actions.get(decision_id)
            if record is None:
                raise ValueError("Unknown decision_id")
            if record["status"] in ("expired", "removed"):
                return record.copy()
            dpid = int(str(record["request"]["dpid"]), 16)
            datapath = self.datapaths.get(dpid)
            if datapath is None:
                raise ValueError("Requested switch is not connected")
            parser, ofp = datapath.ofproto_parser, datapath.ofproto
            cookie = int(record["cookie"], 16)
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF,
                table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            ))
            barrier = parser.OFPBarrierRequest(datapath)
            datapath.set_xid(barrier)
            self.pending_barriers[(dpid, barrier.xid)] = (decision_id, "remove")
            datapath.send_msg(barrier)
            record["status"] = "removing"
            return record.copy()

    def _mark_expired(self, decision_id):
        with self.lock:
            record = self.actions.get(decision_id)
            if record and record["status"] in ("accepted", "installed"):
                record["status"] = "expired"
                record["expired_at"] = time.time()

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, event):
        key = (event.msg.datapath.id, event.msg.xid)
        with self.lock:
            pending = self.pending_barriers.pop(key, None)
            if pending and pending[0] in self.actions:
                decision_id, operation = pending
                if operation == "install":
                    self.actions[decision_id]["status"] = "installed"
                    self.actions[decision_id]["installed_at"] = time.time()
                else:
                    self.actions[decision_id]["status"] = "removed"
                    self.actions[decision_id]["removed_at"] = time.time()

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, event):
        cookie = event.msg.cookie
        if cookie & COOKIE_MASK != COOKIE_PREFIX:
            return
        with self.lock:
            for record in self.actions.values():
                if (
                    int(record["cookie"], 16) == cookie
                    and record["status"] in ("accepted", "installed")
                ):
                    record["status"] = "expired"
                    record["expired_at"] = time.time()
                    break

    def switches(self):
        with self.lock:
            return [{
                "dpid": f"{dpid:016x}",
                "bindings": dict(sorted(self.mac_to_port.get(dpid, {}).items())),
            } for dpid in sorted(self.datapaths)]


class _ActionHandler(BaseHTTPRequestHandler):
    app = None

    def log_message(self, fmt, *args):
        self.app.logger.info("action-api " + fmt, *args)

    def _send(self, value, status=200):
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/switches":
            self._send({"switches": self.app.switches()})
            return
        if self.path == "/v1/actions":
            with self.app.lock:
                actions = [dict(value) for _, value in sorted(self.app.actions.items())]
            self._send({"actions": actions})
            return
        prefix = "/v1/actions/"
        if self.path.startswith(prefix):
            decision_id = self.path[len(prefix):]
            with self.app.lock:
                record = self.app.actions.get(decision_id)
            self._send(record or {"status": "not_found"}, 200 if record else 404)
            return
        self._send({"status": "not_found"}, 404)

    def do_POST(self):
        if self.path != "/v1/actions":
            self._send({"status": "not_found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("Invalid action request size")
            value = json.loads(self.rfile.read(length))
            self._send(self.app.install_action(value))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            self._send({"status": "rejected", "error": str(error)}, 409)

    def do_DELETE(self):
        prefix = "/v1/actions/"
        if not self.path.startswith(prefix):
            self._send({"status": "not_found"}, 404)
            return
        try:
            self._send(self.app.revoke_action(self.path[len(prefix):]))
        except (ValueError, TypeError, KeyError) as error:
            self._send({"status": "rejected", "error": str(error)}, 409)

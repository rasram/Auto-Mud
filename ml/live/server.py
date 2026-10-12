"""Bounded local HTTP API; live sensor/SDN acquisition belongs to integration."""
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
from pathlib import Path
import threading
from ml.live.engine import LiveEngine


def read_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text())
    config['_root'] = str((path.parent / config.get('project_root', '../../..')).resolve())
    if config.get('host', '127.0.0.1') not in ('127.0.0.1', '::1', 'localhost'):
        if not os.environ.get(config.get('api_token_env', 'AUTOMUD_GNN_API_TOKEN')):
            raise ValueError('A non-loopback listener requires the configured API token')
    return config


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, engine):
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        self.engine = engine
        self.slots = threading.BoundedSemaphore(engine.config.get('max_connections', 8))
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                body = b'{"error":{"code":"busy","message":"Retry this same window later"}}'
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'AutoMUD-GNN/1'

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.engine.config.get('request_timeout_seconds', 15))

    def log_message(self, format, *args):
        # No authorization header, body, device identity or raw path is logged.
        pass

    def reply(self, status, value, replay=False):
        body = json.dumps(value, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        if replay:
            self.send_header('X-AutoMUD-Replay', 'true')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Accepted state is durable; retry returns the cached result.

    def authorized(self, admin=False):
        config = self.server.engine.config
        variable = config.get('admin_token_env' if admin else 'api_token_env',
                              'AUTOMUD_GNN_ADMIN_TOKEN' if admin else 'AUTOMUD_GNN_API_TOKEN')
        token = os.environ.get(variable)
        if admin and not token:
            self.reply(403, dict(error=dict(code='admin_disabled', message='Configure the admin token to enable model/session operations')))
            return False
        if token and not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + token):
            self.reply(401, dict(error=dict(code='unauthorized', message='Bearer token required')))
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path in ('/healthz', '/readyz'):
            value = self.server.engine.health()
            self.reply(503 if self.path == '/readyz' and not value['ready'] else 200, value)
        elif self.path == '/v1/model':
            with self.server.engine.lock:
                self.reply(200, self.server.engine.model_info())
        elif self.path == '/v1/contracts':
            root = Path(__file__).resolve().parents[2] / 'configs/gnn/live'
            self.reply(200, dict(input=json.loads((root / 'window.schema.json').read_text()),
                                 output=json.loads((root / 'evidence.schema.json').read_text())))
        else:
            self.reply(404, dict(error=dict(code='not_found', message='Unknown endpoint')))

    def do_POST(self):
        routes = {'/v1/windows', '/v1/models/stage', '/v1/models/activate', '/v1/models/rollback', '/v1/sessions/reset'}
        if self.path not in routes:
            self.reply(404, dict(error=dict(code='not_found', message='Unknown endpoint')))
            return
        if not self.authorized(admin=self.path != '/v1/windows'):
            return
        try:
            if not self.headers.get('Content-Type', '').startswith('application/json'):
                self.reply(415, dict(error=dict(code='content_type', message='Use application/json')))
                return
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= length <= self.server.engine.config.get('max_request_bytes', 4194304):
                self.reply(413, dict(error=dict(code='request_size', message='Missing or excessive Content-Length')))
                return
            def invalid_constant(value):
                raise ValueError('Nonfinite JSON number: ' + value)
            value = json.loads(self.rfile.read(length), parse_constant=invalid_constant)
            if not isinstance(value, dict):
                raise ValueError('Expected JSON object')
            replay = False
            engine = self.server.engine
            if self.path == '/v1/windows':
                result, replay = engine.submit(value)
            elif self.path == '/v1/models/stage':
                if set(value) != {'bundle'}:
                    raise ValueError('Expected bundle path only')
                result = engine.stage(value['bundle'])
            elif self.path == '/v1/models/activate':
                if set(value) != {'bundle_id'}:
                    raise ValueError('Expected staged bundle_id only')
                result = engine.activate(value['bundle_id'])
            elif self.path == '/v1/models/rollback':
                if set(value) != {'bundle_id'}:
                    raise ValueError('Expected rollback target bundle_id')
                result = engine.rollback(value['bundle_id'])
            else:
                if set(value) != {'run_id', 'session_id', 'sensor_id'}:
                    raise ValueError('Expected run/session/sensor identifiers')
                result = engine.reset_session(**value)
            self.reply(200, result, replay)
        except (ValueError, KeyError, TypeError) as error:
            message = str(error)
            status = 409 if 'duplicate' in message or 'Out-of-order' in message else 422
            if 'limit exceeded' in message:
                status = 429
            if self.path == '/v1/windows' and ('Bundle ' in message or 'Nonfinite model' in message):
                status = 503
            with self.server.engine.lock:
                self.server.engine.stats['failures'] += 1
                self.server.engine.last_error = message
            self.reply(status, dict(error=dict(code='processing_failed' if status == 503 else 'conflict' if status == 409 else 'capacity' if status == 429 else 'invalid_request', message=message)))
        except Exception:
            with self.server.engine.lock:
                self.server.engine.stats['failures'] += 1
                self.server.engine.last_error = 'Processing or persistence failed; input was not accepted'
            self.reply(503, dict(error=dict(code='processing_failed', message='Input not accepted; inspect service state and retry this window')))


def serve(config_path):
    config = read_config(config_path)
    engine = LiveEngine(config)
    server = Server((config.get('host', '127.0.0.1'), config.get('port', 8001)), engine)
    print(json.dumps(dict(event='ready', host=server.server_address[0], port=server.server_address[1], model=engine.model_info())), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        engine.close()

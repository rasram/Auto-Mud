"""Small standard-library client for the orchestrator; no ML dependencies here."""
import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class Client:
    def __init__(self, url='http://127.0.0.1:8001', token=None, timeout=30, retries=2):
        self.url, self.token, self.timeout, self.retries = url.rstrip('/'), token, timeout, retries

    def call(self, path, value=None):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        # Serialize once so each retry has the same idempotency digest.
        data = json.dumps(value, allow_nan=False).encode() if value is not None else None
        retry_safe = value is None or path in ('/v1/windows', '/v1/models/stage', '/v1/models/activate', '/v1/models/rollback')
        for attempt in range(self.retries + 1):
            try:
                request = Request(self.url + path, data=data, headers=headers)
                with urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read())
            except HTTPError as error:
                if not retry_safe or error.code not in (429, 503) or attempt == self.retries:
                    raise
                time.sleep(min(2., .5 * (attempt + 1)))
            except (TimeoutError, ConnectionError, OSError):
                if not retry_safe or attempt == self.retries:
                    raise
                time.sleep(min(2., .5 * (attempt + 1)))

    def submit(self, window):
        return self.call('/v1/windows', window)

    def health(self):
        return self.call('/healthz')

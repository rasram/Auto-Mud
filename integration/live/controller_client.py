import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class ControllerClient:
    def __init__(self, url, timeout=5):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def install(self, action):
        body = json.dumps(action, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        request = Request(self.url + "/v1/actions", data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Controller rejected action ({error.code}): {detail}") from error

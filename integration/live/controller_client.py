import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class ControllerClient:
    def __init__(self, url, timeout=5):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def _call(self, path, method="GET", value=None):
        body = None if value is None else json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode()
        request = Request(
            self.url + path, data=body, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Controller rejected action ({error.code}): {detail}") from error

    def install(self, action, confirm_timeout=5):
        body = json.dumps(action, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        request = Request(self.url + "/v1/actions", data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                accepted = json.loads(response.read())
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Controller rejected action ({error.code}): {detail}") from error
        deadline = time.monotonic() + confirm_timeout
        result = accepted
        while result.get("status") == "accepted" and time.monotonic() < deadline:
            time.sleep(0.05)
            result = self._call("/v1/actions/" + action["decision_id"])
        if result.get("status") != "installed":
            raise RuntimeError("Controller did not confirm action installation")
        return result

    def revoke(self, decision_id, confirm_timeout=5):
        result = self._call("/v1/actions/" + decision_id, method="DELETE")
        deadline = time.monotonic() + confirm_timeout
        while result.get("status") == "removing" and time.monotonic() < deadline:
            time.sleep(0.05)
            result = self._call("/v1/actions/" + decision_id)
        if result.get("status") not in ("removed", "expired"):
            raise RuntimeError("Controller did not confirm action removal")
        return result

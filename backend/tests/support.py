"""Shared test utilities, constants and classes (imported by conftest and tests).

This module holds non-fixture testing infrastructure that tests in any
subdirectory need to access. Fixtures remain in conftest.py, which pytest
discovers and applies automatically to all test modules.
"""

import socket
import threading
import time

import httpx
import uvicorn

# v2: user-facing server value is a bare host; the backend appends the port.
NGFW_SERVER = "192.168.1.1"
NGFW_PORT = 8443  # must equal conf STUCK_NGFW_PORT default
BASE_URL = f"https://{NGFW_SERVER}:{NGFW_PORT}"

# Cookie name must match a prefix from app/ngfw/client.py:_NGFW_COOKIE_PREFIXES.
NGFW_SESSION_COOKIE = "insecure-ideco-session"
NGFW_SESSION_VALUE = "mock-ngfw-session-token"
ROTATED_NGFW_SESSION_VALUE = "rotated-ngfw-session-token"

DEFAULT_USERS = [
    {
        "id": "user.id.1",
        "name": "John Doe",
        "login": "john",
        "enabled": True,
        "domain_type": "local",
        "parent_id": None,
    },
    {
        "id": "user.id.2",
        "name": "Jane Smith",
        "login": "jane",
        "enabled": False,
        "domain_type": "ad",
        "parent_id": "group.id.1",
    },
]


class LiveTestClient:
    """HTTP client backed by a local Uvicorn server.

    Starlette 1.x's in-process test transports currently stall on Python 3.14
    while handling some response bodies. A live loopback server exercises the
    production ASGI/HTTP path and keeps the test suite compatible with current
    FastAPI, Starlette and httpx releases.
    """

    def __init__(self, app) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            self._port = int(probe.getsockname()[1])

        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self._port, log_level="warning", access_log=False)
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 5
        while not self._server.started and self._thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self._server.started:
            self._server.should_exit = True
            self._thread.join(timeout=1)
            raise RuntimeError("local Uvicorn test server did not start")

        # The application can assemble a complete rule snapshot before sending
        # a trace response. CI runners occasionally need longer than httpx's
        # five-second default to schedule that local Uvicorn thread; this is a
        # test-transport timeout only and does not affect NGFW request limits.
        self._client = httpx.Client(base_url=f"http://127.0.0.1:{self._port}", timeout=15.0)
        self.cookies = self._client.cookies

    def get(self, url: str, **kwargs):
        return self._client.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._client.post(url, **kwargs)

    def close(self) -> None:
        self._client.close()
        self._server.should_exit = True
        self._thread.join(timeout=5)

"""pytest fixtures for STUCK backend tests (contract v2.1).

Mocking pattern: the ``ngfw_mock`` fixture registers ONE respx route per NGFW
endpoint (paths copied verbatim from app/ngfw/endpoints.py and
app/ngfw/client.py). Every route handler reads its response from a mutable
``state`` dict, so tests change NGFW behaviour by mutating state — never by
re-registering routes (respx matches the first registered route):

    ngfw_mock.state["login"] = (401, {})                      # HTTP status + body
    ngfw_mock.state["users"] = (200, [...])                   # replace payload
    ngfw_mock.state["login"] = httpx.ConnectError("boom")     # raise transport error

Call assertions go through ``ngfw_mock.routes[key].called / .call_count``.

v2: the admin enters a bare host (IP/domain, NO port); the backend builds the
NGFW base URL as https://<host>:<STUCK_NGFW_PORT> (default 8443) — the mocks
match that URL.
"""

import os
import re
import socket
import threading
import time
from typing import Any

import httpx
import pytest
import respx
import uvicorn
from fastapi.testclient import TestClient

# Tests use mocked NGFW URLs and explicitly opt into unrestricted lab mode.
os.environ.setdefault("STUCK_ALLOW_ANY_NGFW", "true")

from app.main import create_app

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


def default_state() -> dict[str, Any]:
    """Default happy-path NGFW responses: (status, json_body) per endpoint key."""
    return {
        # auth (app/ngfw/client.py)
        "login": (200, {"success": True}),
        # The access diagnostic must stay private to the backend.  This is a
        # full read-only administrator profile, which is allowed to trace.
        "whoami": (
            200,
            {
                "login": "admin",
                "name": "Read-only Admin",
                "role_id": "predefined_admin_readonly",
                "role_name": "Read-only administrator",
                "competence": ["admin_read"],
            },
        ),
        "logout": (200, {}),
        # snapshot endpoints (app/ngfw/endpoints.py:load_snapshot)
        "users": (200, DEFAULT_USERS),
        "aliases": (200, []),
        "fw_forward": (200, []),
        "fw_input": (200, []),
        "fw_dnat": (200, []),
        "fw_snat": (200, []),
        "fw_pre_filter": (
            200,
            (
                '"Rule type";"Protocol";"Source IP-address";"Source port";'
                '"Destination IP-address";"Destination port";"TCP-flags";'
                '"TCP-flags to blocking";"Packet length, bytes";"Comment";"Enabled"\r\n'
            ),
        ),
        "fw_settings": (200, {"automatic_snat_enabled": False}),
        # Hardware filtering: source-IP mode active, no rules configured.
        "hw_settings": (200, {"mode": "src-ip"}),
        "hw_rules_mac": (200, []),
        "hw_rules_src_ip": (200, []),
        "hw_rules_dst_ip": (200, []),
        "hw_rules_src_dst_ip": (200, []),
        # Interface settings reduced to LAN networks (192.0.2.0/24 is the lab
        # LAN in these fixtures) + local DNS zones (empty by default).
        "connection_settings": (
            200,
            [
                {"id": "if.lan", "enabled": True, "role": "lan", "l3": ["192.0.2.254/24"], "type": "ethernet"},
                {"id": "if.wan", "enabled": True, "role": "wan", "l3": ["198.51.100.2/30"], "type": "ethernet"},
            ],
        ),
        "dns_zones_forward": (200, []),
        "dns_zones_master": (200, []),
        "interface_state": (200, [{"id": "lan", "l3": ["192.0.2.254/24"], "status": "up"}]),
        "fw_state": (200, {"enabled": True}),
        "cf_state": (200, {"enabled": True}),
        "cf_rules": (200, []),
        "cf_categories": (200, []),
        "shaper_state": (200, {"enabled": True}),
        "shaper_rules_before": (200, []),
        "shaper_rules": (200, []),
        "shaper_rules_after": (200, []),
        "ips_state": (200, {"enabled": True}),
        "ips_bypass": (200, []),
        "av_state": (200, {"enabled": True}),
        "av_profile": (200, {"profile_id": "av_profile.id.default"}),
        "av_profiles": (200, [{"id": "default", "enabled": True}]),
        # trace-time call (app/ngfw/endpoints.py:categorize) — GET with ?url=
        "categorize": (200, {"all": [], "sky": [], "normalizedUrl": ""}),
        "auth_sessions": (
            200,
            [
                {"id": "s1", "user_object_id": "user.id.1", "subnet": "192.0.2.10/32"},
                {"id": "s2", "user_object_id": "user.id.2", "subnet": "192.0.2.11/32"},
            ],
        ),
        "auth_rules": (200, []),
    }


class NgfwMock:
    """Handle yielded by ``ngfw_mock``: mutable state + named respx routes."""

    def __init__(
        self,
        router: respx.MockRouter,
        state: dict[str, Any],
        routes: dict[str, respx.Route],
    ) -> None:
        self.router = router
        self.state = state
        self.routes = routes


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


def _make_handler(state: dict[str, Any], key: str, *, login: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        value = state[key]
        if isinstance(value, Exception):
            raise value
        status, body = value
        headers: list[tuple[str, str]] = []
        if login and status == 200 and state.get("login_sets_cookie", True):
            # NB: one header pair per Set-Cookie; never comma-join cookies.
            headers.append(("set-cookie", f"{NGFW_SESSION_COOKIE}={NGFW_SESSION_VALUE}; Path=/"))
        if key == "whoami" and status == 200 and state.get("whoami_sets_cookie", False):
            headers.append(("set-cookie", f"{NGFW_SESSION_COOKIE}={ROTATED_NGFW_SESSION_VALUE}; Path=/"))
        if isinstance(body, str):
            return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(status, json=body, headers=headers)

    return handler


@pytest.fixture
def ngfw_mock():
    """Mock every NGFW endpoint the backend calls, driven by mutable state."""
    state = default_state()
    with respx.mock(assert_all_called=False) as router:
        routes: dict[str, respx.Route] = {}
        # The test client reaches the temporary local Uvicorn server over real
        # loopback HTTP. Let that traffic pass through; only the app's outbound
        # HTTPS calls to the mocked NGFW belong to respx.
        router.route(url__regex=re.compile(r"http://127\.0\.0\.1:\d+/.*")).pass_through()

        def reg(key: str, method: str, path: str, **handler_kw) -> None:
            routes[key] = router.request(method, f"{BASE_URL}{path}").mock(
                side_effect=_make_handler(state, key, **handler_kw)
            )

        reg("login", "POST", "/web/auth/login", login=True)
        reg("whoami", "GET", "/web/whoami")
        reg("logout", "DELETE", "/web/auth/login")
        reg("users", "GET", "/user_backend/users")
        reg("aliases", "GET", "/aliases/all")
        reg("fw_forward", "GET", "/firewall/rules/forward")
        reg("fw_input", "GET", "/firewall/rules/input")
        reg("fw_dnat", "GET", "/firewall/rules/dnat")
        reg("fw_snat", "GET", "/firewall/rules/snat")
        reg("fw_pre_filter", "GET", "/firewall/rules/drop_rules/export")
        reg("fw_settings", "GET", "/firewall/settings")
        reg("hw_settings", "GET", "/firewall/hw_settings")
        reg("hw_rules_mac", "GET", "/firewall/hw_rules_mac")
        reg("hw_rules_src_ip", "GET", "/firewall/hw_rules_src_ip")
        reg("hw_rules_dst_ip", "GET", "/firewall/hw_rules_dst_ip")
        reg("hw_rules_src_dst_ip", "GET", "/firewall/hw_rules_src_dst_ip")
        reg("connection_settings", "GET", "/l2manager/connection_settings")
        reg("dns_zones_forward", "GET", "/dns/zones/forward")
        reg("dns_zones_master", "GET", "/dns/zones/master")
        reg("interface_state", "GET", "/l2manager/connection_state")
        reg("fw_state", "GET", "/firewall/state")
        reg("cf_state", "GET", "/content-filter/state")
        reg("cf_rules", "GET", "/content-filter/rules")
        reg("cf_categories", "GET", "/content-filter/categories")
        reg("shaper_state", "GET", "/api/shaper/state")
        reg("shaper_rules_before", "GET", "/api/shaper/rules/before")
        reg("shaper_rules", "GET", "/api/shaper/rules")
        reg("shaper_rules_after", "GET", "/api/shaper/rules/after")
        reg("ips_state", "GET", "/ips/state")
        reg("ips_bypass", "GET", "/ips/bypass")
        reg("av_state", "GET", "/av_backend/state")
        reg("av_profile", "GET", "/av_backend/profiles/default")
        reg("av_profiles", "GET", "/av_backend/profiles")
        # categorize is called with ?url=... — match by path, ignore params.
        reg("categorize", "GET", "/content-filter/categorize")
        reg("auth_sessions", "GET", "/monitor_backend/auth_sessions")
        reg("auth_rules", "GET", "/auth/rules")

        yield NgfwMock(router, state, routes)


@pytest.fixture
def app():
    """Fresh FastAPI application (fresh in-memory session store / binding pool)."""
    application = create_app()
    # Tests exercise an HTTP in-process transport. The production Docker
    # profile remains HTTPS-only and retains STUCK_COOKIE_SECURE=true.
    application.state.settings.STUCK_COOKIE_SECURE = False
    return application


@pytest.fixture
def client(app):
    """Current httpx ASGI transport with persistent cookie state."""
    test_client = LiveTestClient(app)
    yield test_client
    test_client.close()


@pytest.fixture
def session_store(app):
    return app.state.session_store


@pytest.fixture
def binding_pool(app):
    return app.state.binding_pool


@pytest.fixture
def settings(app):
    return app.state.settings


@pytest.fixture
def valid_login_data():
    return {
        "login": "admin",
        "password": "s3cret-Passw0rd",
        "server": NGFW_SERVER,  # v2: bare host, no port
    }


@pytest.fixture
def authenticated_client(client: TestClient, ngfw_mock, valid_login_data):
    """TestClient that has already logged in (NGFW mocked with defaults)."""
    resp = client.post("/api/auth/login", json=valid_login_data)
    assert resp.status_code == 200, f"login failed in fixture: {resp.text}"
    return client

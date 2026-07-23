"""Tests for STUCK_REQUIRE_READONLY_ADMIN opt-in mode (readonly_admin_required error).

Contract: docs/API_CONTRACT.md.
Scenario: When STUCK_REQUIRE_READONLY_ADMIN=true, only admins with
predefined_admin_readonly role can log in; any other role is rejected with
readonly_admin_required error (403) after successful NGFW authentication.
"""

import json

from conftest import NGFW_SERVER, NGFW_SESSION_VALUE
from fastapi.testclient import TestClient


def _stuck_session_cookie_set(resp) -> bool:
    """Check if stuck_session cookie is set in response."""
    for header, value in resp.headers.multi_items():
        if header.lower() == "set-cookie" and "stuck_session" in value:
            return True
    return False


def _stuck_2fa_cookie_header(resp) -> str | None:
    """Extract stuck_2fa Set-Cookie header from response."""
    for header, value in resp.headers.multi_items():
        if header.lower() == "set-cookie" and "stuck_2fa" in value:
            return value
    return None


class TestReadonlyAdminModeDisabled:
    """Regression: when STUCK_REQUIRE_READONLY_ADMIN is False (default), all roles work."""

    def test_write_admin_can_login_when_mode_disabled(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """Full admin (predefined_admin_write) can log in when mode is disabled (default)."""
        # Verify mode is disabled by default
        assert settings.STUCK_REQUIRE_READONLY_ADMIN is False

        # Mock NGFW to return a write admin
        ngfw_mock.state["whoami"] = (
            200,
            {
                "login": "admin",
                "name": "Full Administrator",
                "role_id": "predefined_admin_write",
                "role_name": "Administrator",
                "competence": ["admin_read", "admin_write"],
            },
        )

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["session"]["login"] == valid_login_data["login"]
        assert _stuck_session_cookie_set(resp) is True


class TestReadonlyAdminModeEnabled:
    """STUCK_REQUIRE_READONLY_ADMIN=true: only predefined_admin_readonly is accepted."""

    def test_readonly_admin_can_login_when_mode_enabled(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """Read-only admin (predefined_admin_readonly) logs in successfully when mode is enabled."""
        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        # Default mock state already has predefined_admin_readonly role
        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["session"]["login"] == valid_login_data["login"]
        assert data["session"]["server"] == NGFW_SERVER
        assert "expires_at" in data["session"]
        assert _stuck_session_cookie_set(resp) is True

    def test_write_admin_rejected_at_login_when_mode_enabled(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """Full admin (predefined_admin_write) is rejected at /login when mode is enabled (403)."""
        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        # Mock NGFW to return a write admin
        ngfw_mock.state["whoami"] = (
            200,
            {
                "login": "admin",
                "name": "Full Administrator",
                "role_id": "predefined_admin_write",
                "role_name": "Administrator",
                "competence": ["admin_read", "admin_write"],
            },
        )

        resp = client.post("/api/auth/login", json=valid_login_data)

        # Must return 403 with readonly_admin_required error
        assert resp.status_code == 403
        data = resp.json()
        assert data["error"]["code"] == "readonly_admin_required"
        # Details must include the role_id
        assert "details" in data["error"]
        assert data["error"]["details"]["role_id"] == "predefined_admin_write"
        # No session cookie must be set
        assert _stuck_session_cookie_set(resp) is False
        # No NGFW session value must leak
        assert NGFW_SESSION_VALUE not in resp.text

    def test_write_admin_rejection_calls_ngfw_logout(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """Rejecting a write admin must call ngfw_logout to clean up the provisional session."""
        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        ngfw_mock.state["whoami"] = (
            200,
            {
                "login": "admin",
                "name": "Full Administrator",
                "role_id": "predefined_admin_write",
                "role_name": "Administrator",
                "competence": ["admin_read", "admin_write"],
            },
        )

        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 403

        # Verify ngfw_logout was called (DELETE /web/auth/login)
        assert ngfw_mock.routes["logout"].called

    def test_error_response_contains_no_secrets(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """Error response must not contain password, NGFW cookie, or session id."""
        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        ngfw_mock.state["whoami"] = (
            200,
            {
                "login": "admin",
                "name": "Full Administrator",
                "role_id": "predefined_admin_write",
                "role_name": "Administrator",
                "competence": ["admin_read", "admin_write"],
            },
        )

        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 403

        response_text = json.dumps(resp.json())
        # No password
        assert valid_login_data["password"] not in response_text
        # No NGFW session value
        assert NGFW_SESSION_VALUE not in response_text
        # Role id is safe metadata (same policy as insufficient_ngfw_permissions)
        assert "predefined_admin_write" in response_text


class TestTwoFactorWithReadonlyAdminMode:
    """2FA flow with STUCK_REQUIRE_READONLY_ADMIN: role check happens after code acceptance."""

    def test_two_factor_pending_regardless_of_mode(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """2FA login opens the code form even when mode is enabled (check comes after 2FA)."""
        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        # Mock a blocked profile (2FA required)
        blocked_whoami = {
            "login": "mfa",
            "blocked_flags": 1,
            "role_id": "",
            "role_name": "",
            "two_factor": "",
            "admin_id": "admin.id.123",
        }
        ngfw_mock.state["whoami"] = (200, blocked_whoami)

        resp = client.post("/api/auth/login", json=valid_login_data)

        # Must return two_factor_required (role check is deferred until after code)
        assert resp.status_code == 200
        data = resp.json()
        assert data["two_factor_required"] is True
        assert _stuck_2fa_cookie_header(resp) is not None
        assert _stuck_session_cookie_set(resp) is False

    def test_2fa_write_admin_rejected_after_code_acceptance(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """After 2FA code acceptance, if whoami shows write role, reject with 403."""
        from app.ngfw.two_factor_ws import MSG_SUCCESS, TwoFactorMessage

        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        # Original blocked state (2FA required)
        blocked_whoami = {
            "login": "mfa",
            "blocked_flags": 1,
            "role_id": "",
            "role_name": "",
            "two_factor": "",
            "admin_id": "admin.id.123",
        }
        ngfw_mock.state["whoami"] = (200, blocked_whoami)

        # Fake the WebSocket channel for 2FA
        _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage(MSG_SUCCESS)])

        # Step 1: Login → goes to 2FA form
        resp_login = client.post("/api/auth/login", json=valid_login_data)
        assert resp_login.status_code == 200
        assert resp_login.json()["two_factor_required"] is True

        # Step 2: Submit 2FA code, but whoami now reveals write admin role
        write_admin_whoami = {
            "login": "admin",
            "name": "Full Administrator",
            "role_id": "predefined_admin_write",
            "role_name": "Administrator",
            "competence": ["admin_read", "admin_write"],
        }
        ngfw_mock.state["whoami"] = (200, write_admin_whoami)

        resp_2fa = client.post("/api/auth/2fa", json={"code": "123456"})

        # Must return 403 readonly_admin_required
        assert resp_2fa.status_code == 403
        data = resp_2fa.json()
        assert data["error"]["code"] == "readonly_admin_required"
        assert data["error"]["details"]["role_id"] == "predefined_admin_write"
        # No session cookie
        assert _stuck_session_cookie_set(resp_2fa) is False
        # No NGFW session value must leak
        assert NGFW_SESSION_VALUE not in resp_2fa.text

    def test_2fa_readonly_admin_succeeds_after_code_acceptance(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """After 2FA code acceptance, if whoami shows read-only role, login succeeds (positive)."""
        from app.ngfw.two_factor_ws import MSG_SUCCESS, TwoFactorMessage

        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        # Original blocked state (2FA required)
        blocked_whoami = {
            "login": "mfa",
            "blocked_flags": 1,
            "role_id": "",
            "role_name": "",
            "two_factor": "",
            "admin_id": "admin.id.123",
        }
        ngfw_mock.state["whoami"] = (200, blocked_whoami)

        # Fake the WebSocket channel for 2FA
        _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage(MSG_SUCCESS)])

        # Step 1: Login → goes to 2FA form
        resp_login = client.post("/api/auth/login", json=valid_login_data)
        assert resp_login.status_code == 200
        assert resp_login.json()["two_factor_required"] is True

        # Step 2: Submit 2FA code, whoami shows read-only admin role
        readonly_whoami = {
            "login": "admin",
            "name": "Read-only Admin",
            "role_id": "predefined_admin_readonly",
            "role_name": "Read-only administrator",
            "competence": ["admin_read"],
        }
        ngfw_mock.state["whoami"] = (200, readonly_whoami)

        resp_2fa = client.post("/api/auth/2fa", json={"code": "123456"})

        # Must succeed and create session
        assert resp_2fa.status_code == 200
        data = resp_2fa.json()
        assert data["ok"] is True
        assert "session" in data
        assert data["session"]["login"] == "admin"
        assert _stuck_session_cookie_set(resp_2fa) is True
        # 2FA cookie must be cleared (not MaxAge=0, cleared in the response)
        cookie_header = _stuck_2fa_cookie_header(resp_2fa)
        assert cookie_header is not None
        assert "max-age=0" in cookie_header.lower() or 'stuck_2fa=""' in cookie_header

    def test_2fa_rejection_calls_ngfw_logout(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        """Rejecting a write admin in 2FA must close the provisional NGFW session."""
        from app.ngfw.two_factor_ws import MSG_SUCCESS, TwoFactorMessage

        monkeypatch.setattr(settings, "STUCK_REQUIRE_READONLY_ADMIN", True)

        blocked_whoami = {
            "login": "mfa",
            "blocked_flags": 1,
            "role_id": "",
            "role_name": "",
            "two_factor": "",
            "admin_id": "admin.id.123",
        }
        ngfw_mock.state["whoami"] = (200, blocked_whoami)

        _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage(MSG_SUCCESS)])

        client.post("/api/auth/login", json=valid_login_data)

        # Change to write admin
        ngfw_mock.state["whoami"] = (
            200,
            {
                "login": "admin",
                "name": "Full Administrator",
                "role_id": "predefined_admin_write",
                "role_name": "Administrator",
                "competence": ["admin_read", "admin_write"],
            },
        )

        resp = client.post("/api/auth/2fa", json={"code": "123456"})
        assert resp.status_code == 403

        # Verify logout was called in the 2FA rejection (it may have been called
        # during login as well if there were stale 2FA pending entries, so we just
        # verify it's true now)
        assert ngfw_mock.routes["logout"].called


# --------------------------------------------------------------------------- #
# Helper: fake WebSocket channel installation for 2FA tests.                 #
# Copied pattern from test_two_factor.py.                                    #
# --------------------------------------------------------------------------- #


def _install_fake_channel(monkeypatch, frames):
    """Script the challenge socket for a whole 2FA session.

    ``frames`` is the full sequence the channel's ``recv_typed`` yields
    across all attempts. Returns a holder whose ``channels`` list grows
    one entry per opened socket.
    """
    from app.errors import StuckError

    holder: dict = {"channels": []}

    class _FakeChannel:
        def __init__(self, server, cookies):
            self.server = server
            self.cookies = cookies
            self._frames = list(frames)
            self.sent: list[str] = []
            self.started = False
            self.closed = False
            holder["channels"].append(self)

        async def open(self):
            self.opened = True

        async def send_start(self):
            self.started = True

        async def recv_typed(self, *, timeout=None):
            if not self._frames:
                raise StuckError("second_factor_expired", "no more frames")
            return self._frames.pop(0)

        async def send_code(self, code):
            self.sent.append(code)

        async def close(self):
            self.closed = True

    monkeypatch.setattr("app.api.auth.NgfwTwoFactorChannel", _FakeChannel)
    return holder

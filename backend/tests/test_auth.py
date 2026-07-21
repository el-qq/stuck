"""Tests for authentication endpoints (docs/API_CONTRACT.md)."""

import json
import ipaddress

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import NGFW_SERVER, NGFW_SESSION_VALUE


def _stuck_set_cookie_header(resp) -> str | None:
    for header, value in resp.headers.multi_items():
        if header.lower() == "set-cookie" and "stuck_session" in value:
            return value
    return None


class TestLogin:
    """POST /api/auth/login — login and session creation."""

    def test_successful_login(self, client: TestClient, ngfw_mock, valid_login_data):
        """Login with valid credentials returns v2 session info and sets the cookie."""
        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["session"]["login"] == valid_login_data["login"]
        assert data["session"]["server"] == NGFW_SERVER  # bare host, no port
        assert "expires_at" in data["session"]
        assert data["session"]["first_login"] is True
        # v2: rules_updated_at present and null before the first snapshot load.
        assert "rules_updated_at" in data["session"]
        assert data["session"]["rules_updated_at"] is None

        assert "stuck_session" in resp.cookies

    def test_cookie_flags(self, client: TestClient, ngfw_mock, valid_login_data):
        """stuck_session cookie carries HttpOnly, SameSite, Max-Age=36000 (10h, contract §1.1)."""
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200

        set_cookie = _stuck_set_cookie_header(resp)
        assert set_cookie is not None, "stuck_session Set-Cookie header missing"
        assert "HttpOnly" in set_cookie
        assert "SameSite" in set_cookie
        assert "Max-Age=36000" in set_cookie
        assert "Path=/" in set_cookie

    def test_cookie_secure_flag_follows_settings(self, client: TestClient, ngfw_mock, valid_login_data, settings):
        """Secure flag on stuck_session matches STUCK_COOKIE_SECURE setting."""
        resp = client.post("/api/auth/login", json=valid_login_data)
        set_cookie = _stuck_set_cookie_header(resp)
        assert set_cookie is not None
        if settings.STUCK_COOKIE_SECURE:
            assert "Secure" in set_cookie
        else:
            assert "Secure" not in set_cookie

    def test_invalid_credentials(self, client: TestClient, ngfw_mock, valid_login_data):
        """NGFW rejects credentials (401) → error.code=invalid_credentials."""
        ngfw_mock.state["login"] = (401, {"message": "invalid"})

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "invalid_credentials"
        assert "stuck_session" not in resp.cookies

    def test_host_outside_allowlist_is_rejected_before_ngfw_call(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        monkeypatch.setattr(settings, "STUCK_ALLOW_ANY_NGFW", False)
        monkeypatch.setattr(settings, "STUCK_ALLOWED_NGFW_HOSTS", "192.168.200.1")
        monkeypatch.setattr(settings, "STUCK_ALLOWED_NGFW_CIDRS", "")

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "ngfw_host_not_allowed"
        assert not ngfw_mock.routes["login"].called

    def test_configured_default_server_rejects_a_different_api_server(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        monkeypatch.setattr(settings, "STUCK_DEFAULT_SERVER", "192.168.1.99")

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "ngfw_host_not_allowed"
        assert not ngfw_mock.routes["login"].called

    def test_server_unreachable(self, client: TestClient, ngfw_mock, valid_login_data):
        """Connect error to NGFW → error.code=server_unreachable (502)."""
        ngfw_mock.state["login"] = httpx.ConnectError("connection refused")

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "server_unreachable"

    def test_server_timeout(self, client: TestClient, ngfw_mock, valid_login_data):
        """Timeout talking to NGFW → server_unreachable (502)."""
        ngfw_mock.state["login"] = httpx.ConnectTimeout("timed out")

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "server_unreachable"

    @pytest.mark.parametrize(
        "bad_server",
        [
            "192.168.1.1:8443",  # v2: port is no longer allowed
            "ngfw.local:8443",  # port with hostname
            "https://192.168.1.1",  # scheme
            "http://ngfw.local",  # scheme
            "192.168.1.1/api",  # path
            "300.1.2.3",  # numeric but not valid IPv4
            "999.999.999.999",  # numeric but not valid IPv4
            "not a valid address",  # whitespace
            "host_with_underscore",  # invalid hostname char (RFC 1123)
            "-leadinghyphen.com",  # label starts with hyphen
            "   ",  # blank
            "[2001:db8::1]",  # IPv6 literal (rejected by v2 contract)
        ],
    )
    def test_invalid_server_address(self, client: TestClient, ngfw_mock, valid_login_data, bad_server):
        """v2: server must be a bare IP/domain; anything else → invalid_server_address."""
        bad_data = {**valid_login_data, "server": bad_server}

        resp = client.post("/api/auth/login", json=bad_data)

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_server_address"
        # Rejected before any network call.
        assert not ngfw_mock.routes["login"].called

    def test_valid_ipv4_accepted(self, client: TestClient, ngfw_mock, valid_login_data):
        """A valid bare IPv4 is accepted and echoed as-is."""
        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 200
        assert resp.json()["session"]["server"] == NGFW_SERVER

    def test_valid_domain_normalized_to_lowercase(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        """A valid domain is accepted and normalized to lowercase."""
        # Mock the same NGFW login under the domain-based base URL
        # (https://<host>:<STUCK_NGFW_PORT> — the backend appends the port).
        ngfw_mock.router.post("https://ngfw.corp.local:8443/web/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"success": True},
                headers=[("set-cookie", "insecure-ideco-session=tok; Path=/")],
            )
        )

        async def resolve_test_host(host, port):
            assert host == "ngfw.corp.local"
            return {ipaddress.ip_address("192.168.1.1")}

        monkeypatch.setattr("app.domain.ngfw_access.resolve_host_addresses", resolve_test_host)

        data = {**valid_login_data, "server": "NGFW.Corp.Local"}
        resp = client.post("/api/auth/login", json=data)

        assert resp.status_code == 200
        assert resp.json()["session"]["server"] == "ngfw.corp.local"

    def test_ngfw_5xx_maps_to_ngfw_error(self, client: TestClient, ngfw_mock, valid_login_data):
        """NGFW 500 on login → ngfw_error (502)."""
        ngfw_mock.state["login"] = (500, {"message": "boom"})

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "ngfw_error"

    def test_login_200_without_cookie_is_api_changed(self, client: TestClient, ngfw_mock, valid_login_data):
        """NGFW answers 200 but sets no session cookie → api_changed."""
        ngfw_mock.state["login_sets_cookie"] = False

        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_password_not_echoed_in_response(self, client: TestClient, ngfw_mock, valid_login_data):
        """Password never appears in the login response body."""
        resp = client.post("/api/auth/login", json=valid_login_data)

        assert valid_login_data["password"] not in json.dumps(resp.json())

    def test_ngfw_cookie_not_exposed_to_browser(self, client: TestClient, ngfw_mock, valid_login_data):
        """NGFW session cookie never reaches the browser (NFR-S2, contract §5.2)."""
        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 200
        all_set_cookies = " | ".join(v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie")
        assert NGFW_SESSION_VALUE not in all_set_cookies
        assert NGFW_SESSION_VALUE not in resp.text

    def test_login_always_validates_password_via_ngfw(self, client: TestClient, ngfw_mock, valid_login_data):
        """v2 §3.1: every login POSTs /web/auth/login even when rules are pooled."""
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200
        assert client.get("/api/users").status_code == 200  # pool the snapshot
        assert client.post("/api/auth/logout").status_code == 200

        ngfw_mock.state["login"] = (401, {"message": "password changed"})
        resp = client.post("/api/auth/login", json=valid_login_data)

        # Even though the binding has a snapshot, a bad password is rejected.
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "invalid_credentials"

    def test_session_data_calls_recheck_destination_policy(
        self, client: TestClient, ngfw_mock, valid_login_data, settings, monkeypatch
    ):
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200
        monkeypatch.setattr(settings, "STUCK_ALLOW_ANY_NGFW", False)
        monkeypatch.setattr(settings, "STUCK_ALLOWED_NGFW_HOSTS", "192.168.200.1")
        monkeypatch.setattr(settings, "STUCK_ALLOWED_NGFW_CIDRS", "")

        resp = client.get("/api/users")

        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "ngfw_host_not_allowed"
        assert not ngfw_mock.routes["users"].called


class TestLogout:
    """POST /api/auth/logout — v2.1: kills STUCK session + NGFW cookie, keeps the pool."""

    def test_successful_logout(self, authenticated_client: TestClient):
        """Logout returns ok and invalidates the session."""
        resp = authenticated_client.post("/api/auth/logout")

        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        session_resp = authenticated_client.get("/api/session")
        assert session_resp.status_code == 401

    def test_logout_calls_ngfw_delete_best_effort(self, authenticated_client: TestClient, ngfw_mock):
        """v2.1: logout fires DELETE /web/auth/login (kills the NGFW admin session)."""
        assert not ngfw_mock.routes["logout"].called

        resp = authenticated_client.post("/api/auth/logout")

        assert resp.status_code == 200
        assert ngfw_mock.routes["logout"].called

    def test_logout_swallows_ngfw_http_error(self, authenticated_client: TestClient, ngfw_mock):
        """NGFW 500 on DELETE does not break logout (best-effort)."""
        ngfw_mock.state["logout"] = (500, {"message": "boom"})

        resp = authenticated_client.post("/api/auth/logout")

        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_logout_swallows_ngfw_transport_error(self, authenticated_client: TestClient, ngfw_mock):
        """NGFW unreachable on DELETE does not break logout (best-effort)."""
        ngfw_mock.state["logout"] = httpx.ConnectError("gone")

        resp = authenticated_client.post("/api/auth/logout")

        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_logout_idempotent(self, client: TestClient, ngfw_mock):
        """Logout without any session still returns 200 {ok: true} (contract §3.2)."""
        resp = client.post("/api/auth/logout")

        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        # No session -> no NGFW cookie -> no DELETE call.
        assert not ngfw_mock.routes["logout"].called

    def test_logout_twice(self, authenticated_client: TestClient, ngfw_mock):
        """Second logout after the first also succeeds; DELETE fired only once."""
        assert authenticated_client.post("/api/auth/logout").status_code == 200
        resp = authenticated_client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert ngfw_mock.routes["logout"].call_count == 1


class TestSessionEndpoint:
    """GET /api/session — session status (v2: + rules_updated_at)."""

    def test_get_session_authenticated(self, authenticated_client: TestClient, valid_login_data):
        resp = authenticated_client.get("/api/session")

        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["login"] == valid_login_data["login"]
        assert data["server"] == NGFW_SERVER
        assert "expires_at" in data
        # Snapshot not loaded yet (lazy): flag false, timestamp null.
        assert data["rules_loaded"] is False
        assert data["rules_updated_at"] is None

    def test_session_reports_rules_updated_at_after_load(self, authenticated_client: TestClient):
        assert authenticated_client.get("/api/users").status_code == 200

        resp = authenticated_client.get("/api/session")
        data = resp.json()
        assert data["rules_loaded"] is True
        assert isinstance(data["rules_updated_at"], str)

    def test_get_session_without_cookie(self, client: TestClient):
        resp = client.get("/api/session")

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"

    def test_get_session_with_unknown_cookie(self, client: TestClient):
        client.cookies.set("stuck_session", "bogus-session-id")
        resp = client.get("/api/session")

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] in ("not_authenticated", "session_expired")

    def test_expired_session_rejected(self, client: TestClient, ngfw_mock, valid_login_data, session_store):
        """A known STUCK session past its TTL triggers the password re-login flow."""
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200

        for sess in session_store._by_id.values():
            sess.expires_at = sess.created_at - 1

        resp = client.get("/api/session")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "session_expired"

    def test_protected_endpoints_require_session(self, client: TestClient):
        """All protected endpoints return 401 without a cookie (contract §5.1)."""
        assert client.get("/api/session").status_code == 401
        assert client.get("/api/users").status_code == 401
        assert client.post("/api/trace", json={"url": "example.com"}).status_code == 401
        assert client.post("/api/rules/refresh").status_code == 401


class TestNgfwSessionExpired:
    """v2.1 §1.2: expired NGFW cookie → 401 session_expired on ANY NGFW call."""

    def test_users_with_expired_ngfw_cookie(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["users"] = (401, {"message": "unauthorized"})

        resp = authenticated_client.get("/api/users")

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "session_expired"

    def test_refresh_with_expired_ngfw_cookie(self, authenticated_client: TestClient, ngfw_mock):
        # Load the snapshot first, then expire the NGFW cookie (403 variant).
        assert authenticated_client.get("/api/users").status_code == 200
        ngfw_mock.state["users"] = (403, {"message": "forbidden"})

        resp = authenticated_client.post("/api/rules/refresh")

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "session_expired"

    def test_trace_categorize_with_expired_ngfw_cookie(self, authenticated_client: TestClient, ngfw_mock):
        """Snapshot is pooled, but categorize hits NGFW → session_expired surfaces."""
        assert authenticated_client.get("/api/users").status_code == 200
        ngfw_mock.state["categorize"] = (401, {"message": "unauthorized"})

        resp = authenticated_client.post("/api/trace", json={"url": "example.com"})

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "session_expired"

    def test_relogin_after_ngfw_expiry_serves_rules_from_pool(self, client: TestClient, ngfw_mock, valid_login_data):
        """v2.1: after re-login the pool is intact — rules come from cache."""
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200
        assert client.get("/api/users").status_code == 200
        users_calls_after_load = ngfw_mock.routes["users"].call_count

        # NGFW cookie expired: the UI re-logs in after a session_expired error.
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200
        assert resp.json()["session"]["first_login"] is False
        assert resp.json()["session"]["rules_updated_at"] is not None

        # Users served from the pool: no new NGFW /user_backend/users calls.
        resp = client.get("/api/users")
        assert resp.status_code == 200
        assert resp.json()["cached"] is True
        assert ngfw_mock.routes["users"].call_count == users_calls_after_load

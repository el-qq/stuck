"""Tests for API contract compliance (docs/API_CONTRACT.md)."""

import httpx
from fastapi.testclient import TestClient

from app import __version__

KNOWN_CODES = {
    "validation_error",
    "invalid_server_address",
    "ngfw_host_not_allowed",
    "invalid_credentials",
    "second_factor_required",
    "not_authenticated",
    "session_expired",
    "server_unreachable",
    "api_changed",
    "ngfw_error",
    "not_found",
    "internal_error",
}


class TestApiChanged:
    """NGFW schema mismatch → api_changed (contract §2.1, requirement 'изменилось API?')."""

    def test_malformed_users_response(self, authenticated_client: TestClient, ngfw_mock):
        """Users payload is an object instead of a list → api_changed."""
        ngfw_mock.state["users"] = (200, {"not_users": []})

        resp = authenticated_client.get("/api/users")

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_malformed_state_response(self, authenticated_client: TestClient, ngfw_mock):
        """content-filter/state with a non-boolean 'enabled' → api_changed."""
        ngfw_mock.state["cf_state"] = (200, {"enabled": "definitely-not-a-bool"})

        resp = authenticated_client.get("/api/users")

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_malformed_categorize_response(self, authenticated_client: TestClient, ngfw_mock):
        """categorize returns a list instead of an object → api_changed on trace."""
        ngfw_mock.state["categorize"] = (200, [1, 2, 3])

        resp = authenticated_client.post("/api/trace", json={"url": "example.com"})

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_ngfw_unreachable_during_snapshot(self, authenticated_client: TestClient, ngfw_mock):
        """NGFW dies between login and data load → server_unreachable."""
        ngfw_mock.state["users"] = httpx.ConnectError("ngfw went away")

        resp = authenticated_client.get("/api/users")

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "server_unreachable"

    def test_current_content_filter_source_aliases_are_normalized(self):
        from app.ngfw.schemas import ContentFilterRule

        rule = ContentFilterRule.model_validate(
            ContentFilterRule.coerce_id(
                {
                    "id": 7,
                    "name": "User-scoped deny",
                    "src_aliases": [{"aliases": ["user.id.42"], "negate": False}],
                    "categories": ["users.id.5"],
                    "access": "deny",
                }
            )
        )

        assert rule.id == "7"
        assert rule.aliases == ["user.id.42"]


class TestHealthEndpoint:
    def test_health_no_auth(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["version"] == __version__ == "0.1.0"

    def test_health_reports_ngfw_port_default(self, client: TestClient, settings):
        """v2.2 (FR-10.3): health exposes the NGFW port the backend connects to."""
        resp = client.get("/api/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["ngfw_port"] == settings.STUCK_NGFW_PORT
        assert data["ngfw_port"] == 8443  # shipped default
        assert data["ngfw_access_mode"] == "unrestricted"

    def test_health_reports_custom_ngfw_port(self, monkeypatch):
        """STUCK_NGFW_PORT from env/conf is reflected in /api/health (v2.2)."""
        from app.config import get_settings
        from app.main import create_app

        monkeypatch.setenv("STUCK_NGFW_PORT", "9443")
        get_settings.cache_clear()
        try:
            app = create_app()
            client = TestClient(app)
            resp = client.get("/api/health")

            assert resp.status_code == 200
            assert resp.json()["ngfw_port"] == 9443
        finally:
            # Don't leak the custom port into other tests' cached settings.
            get_settings.cache_clear()

    def test_deprecated_public_config_still_responds(self, client: TestClient):
        """GET /api/config exposes non-sensitive UI bootstrap settings."""
        resp = client.get("/api/config")
        assert resp.status_code == 200
        assert "default_server" in resp.json()
        assert resp.json()["trace_animation_enabled"] is True

    def test_public_config_reports_trace_animation_disabled(self, monkeypatch):
        from app.config import get_settings
        from app.main import create_app

        monkeypatch.setenv("STUCK_ENABLE_TRACE_ANIMATION", "false")
        get_settings.cache_clear()
        try:
            client = TestClient(create_app())
            resp = client.get("/api/config")

            assert resp.status_code == 200
            assert resp.json()["trace_animation_enabled"] is False
        finally:
            get_settings.cache_clear()


class TestValidationErrors:
    def test_missing_required_field_login(self, client: TestClient):
        resp = client.post(
            "/api/auth/login",
            json={"login": "admin", "server": "192.168.1.1"},  # no password
        )

        assert resp.status_code == 400
        data = resp.json()
        assert data["error"]["code"] == "validation_error"

    def test_validation_error_does_not_echo_password(self, client: TestClient):
        """validation_error details must not include the submitted password value."""
        secret = "MyS3cretPassw0rd!"
        resp = client.post(
            "/api/auth/login",
            json={"login": "", "password": secret, "server": "192.168.1.1"},
        )

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"
        assert secret not in resp.text

    def test_empty_login_field(self, client: TestClient):
        resp = client.post(
            "/api/auth/login",
            json={"login": "", "password": "password", "server": "192.168.1.1"},
        )

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_trace_bad_port(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "dst_port": 99999})

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_trace_bad_protocol(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "protocol": "icmp"})

        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"


class TestErrorEnvelope:
    """Contract §2: every error is {"error": {"code", "message", details?}}."""

    def test_error_has_code_and_message(self, client: TestClient):
        resp = client.post("/api/auth/login", json={"login": "admin"})

        assert resp.status_code == 400
        err = resp.json()["error"]
        assert isinstance(err["code"], str)
        assert isinstance(err["message"], str)

    def test_error_code_is_known(self, client: TestClient):
        resp = client.post("/api/auth/login", json={"login": "", "password": "", "server": ""})
        assert resp.json()["error"]["code"] in KNOWN_CODES

    def test_401_error_envelope(self, client: TestClient):
        resp = client.get("/api/session")
        assert resp.status_code == 401
        err = resp.json()["error"]
        assert err["code"] in KNOWN_CODES
        assert err["message"]

"""Access-diagnostic tests for the post-login NGFW role check."""

import json

import pytest
from fastapi.testclient import TestClient

from conftest import NGFW_SESSION_VALUE, ROTATED_NGFW_SESSION_VALUE


READONLY_WHOAMI = {
    "login": "admin",
    "name": "Read-only Admin",
    "role_id": "predefined_admin_readonly",
    "role_name": "Read-only administrator",
    "competence": ["admin_read"],
}
DENIED_WHOAMI = {
    "login": "firewall-admin",
    "name": "Firewall Admin",
    "role_id": "predefined_firewall_admin",
    "role_name": "Firewall administrator",
    "competence": ["admin_read"],
}


def _assert_safe_profile(payload: dict, *, role_id: str, role_name: str, trace_allowed: bool) -> None:
    profile = payload["access_profile"]
    assert profile == {
        "role_id": role_id,
        "role_name": role_name,
        "trace_allowed": trace_allowed,
    }
    assert "competence" not in json.dumps(payload)
    assert "Read-only Admin" not in json.dumps(payload)
    assert "Firewall Admin" not in json.dumps(payload)
    assert NGFW_SESSION_VALUE not in json.dumps(payload)


class TestAccessDiagnostic:
    def test_login_checks_whoami_with_the_server_side_ngfw_cookie_and_exposes_only_safe_profile(
        self, client: TestClient, ngfw_mock, valid_login_data
    ):
        """A successful password login must inspect role access before the session is usable."""
        resp = client.post("/api/auth/login", json=valid_login_data)

        assert resp.status_code == 200
        assert ngfw_mock.routes["whoami"].called
        whoami_request = ngfw_mock.routes["whoami"].calls[0].request
        assert "insecure-ideco-session=" in whoami_request.headers["cookie"]
        assert NGFW_SESSION_VALUE in whoami_request.headers["cookie"]

        session = client.get("/api/session")
        assert session.status_code == 200
        _assert_safe_profile(
            session.json(),
            role_id="predefined_admin_readonly",
            role_name="Read-only administrator",
            trace_allowed=True,
        )

        # The browser gets its own opaque STUCK cookie, never an NGFW cookie
        # or the raw whoami body.
        assert NGFW_SESSION_VALUE not in resp.text
        assert NGFW_SESSION_VALUE not in " ".join(
            value for name, value in resp.headers.multi_items() if name.lower() == "set-cookie"
        )

    def test_full_readonly_role_can_load_rules_and_trace(self, client: TestClient, ngfw_mock, valid_login_data):
        """The diagnostic permits the shipped full read-only administrator role."""
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200

        users = client.get("/api/users")
        trace = client.post("/api/trace", json={"url": "example.com"})

        assert users.status_code == 200
        assert trace.status_code == 200
        assert ngfw_mock.routes["users"].called

    def test_session_and_binding_use_the_canonical_whoami_login_not_the_submitted_alias(
        self, client: TestClient, ngfw_mock, valid_login_data, binding_pool
    ):
        """NGFW is authoritative for the canonical administrator identity."""
        submitted = {**valid_login_data, "login": "admin-alias@directory"}

        response = client.post("/api/auth/login", json=submitted)

        assert response.status_code == 200
        session = client.get("/api/session")
        assert session.status_code == 200
        assert session.json()["login"] == READONLY_WHOAMI["login"]
        assert binding_pool.get(READONLY_WHOAMI["login"], valid_login_data["server"]) is not None
        assert binding_pool.get(submitted["login"], valid_login_data["server"]) is None

    def test_malformed_whoami_response_is_api_changed_without_creating_a_stuck_session(
        self, client: TestClient, ngfw_mock, valid_login_data, binding_pool, session_store
    ):
        ngfw_mock.state["whoami"] = (200, {"role_id": "predefined_admin_readonly"})

        response = client.post("/api/auth/login", json=valid_login_data)

        assert response.status_code == 502
        assert response.json()["error"]["code"] == "api_changed"
        assert "stuck_session" not in response.cookies
        assert NGFW_SESSION_VALUE not in response.text
        assert "predefined_admin_readonly" not in response.text
        assert session_store._by_id == {}
        assert binding_pool.get(valid_login_data["login"], valid_login_data["server"]) is None

    def test_whoami_cookie_rotation_stays_server_side_for_later_access_refresh(
        self, client: TestClient, ngfw_mock, valid_login_data
    ):
        ngfw_mock.state["whoami_sets_cookie"] = True
        login = client.post("/api/auth/login", json=valid_login_data)
        assert login.status_code == 200

        ngfw_mock.state["whoami_sets_cookie"] = False
        refreshed = client.post("/api/session/access/refresh")

        assert refreshed.status_code == 200
        second_whoami_request = ngfw_mock.routes["whoami"].calls[1].request
        assert ROTATED_NGFW_SESSION_VALUE in second_whoami_request.headers["cookie"]
        assert NGFW_SESSION_VALUE not in " ".join(
            value for name, value in refreshed.headers.multi_items() if name.lower() == "set-cookie"
        )
        assert ROTATED_NGFW_SESSION_VALUE not in refreshed.text

    @pytest.mark.parametrize(
        ("method", "path", "body"),
        [
            ("get", "/api/users", None),
            ("post", "/api/trace", {"url": "example.com"}),
            ("post", "/api/rules/refresh", None),
            ("get", "/api/rules/export", None),
        ],
    )
    def test_denied_role_blocks_snapshot_consumers_without_loading_a_snapshot(
        self, client: TestClient, ngfw_mock, valid_login_data, binding_pool, method: str, path: str, body: dict | None
    ):
        """Known limited roles stay signed in, but cannot trigger any rule snapshot load."""
        ngfw_mock.state["whoami"] = (200, DENIED_WHOAMI)
        login = client.post("/api/auth/login", json=valid_login_data)

        assert login.status_code == 200
        _assert_safe_profile(
            client.get("/api/session").json(),
            role_id="predefined_firewall_admin",
            role_name="Firewall administrator",
            trace_allowed=False,
        )
        assert binding_pool.get(DENIED_WHOAMI["login"], valid_login_data["server"]) is None
        assert binding_pool.get(valid_login_data["login"], valid_login_data["server"]) is None

        response = getattr(client, method)(path, **({"json": body} if body is not None else {}))

        assert response.status_code == 403
        error = response.json()["error"]
        assert error["code"] == "insufficient_ngfw_permissions"
        assert error["details"] == {"role_id": "predefined_firewall_admin"}
        assert "competence" not in response.text
        assert "Firewall Admin" not in response.text
        assert NGFW_SESSION_VALUE not in response.text
        assert binding_pool.get(DENIED_WHOAMI["login"], valid_login_data["server"]) is None
        assert binding_pool.get(valid_login_data["login"], valid_login_data["server"]) is None
        assert not ngfw_mock.routes["users"].called

    @pytest.mark.parametrize("status", [401, 403])
    def test_whoami_auth_rejection_requires_second_factor_without_creating_a_stuck_session(
        self, client: TestClient, ngfw_mock, valid_login_data, binding_pool, session_store, status: int
    ):
        """A provisional password cookie is not a completed STUCK session."""
        ngfw_mock.state["whoami"] = (status, {"message": "private challenge and token"})

        response = client.post("/api/auth/login", json=valid_login_data)

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "second_factor_required"
        assert "stuck_session" not in response.cookies
        assert NGFW_SESSION_VALUE not in response.text
        assert "private challenge and token" not in response.text
        assert session_store._by_id == {}
        assert binding_pool.get(valid_login_data["login"], valid_login_data["server"]) is None

    def test_access_retry_rechecks_current_session_without_relogging_and_enables_a_now_allowed_role(
        self, client: TestClient, ngfw_mock, valid_login_data, binding_pool
    ):
        ngfw_mock.state["whoami"] = (200, DENIED_WHOAMI)
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200
        assert ngfw_mock.routes["login"].call_count == 1

        ngfw_mock.state["whoami"] = (200, READONLY_WHOAMI)
        response = client.post("/api/session/access/refresh")

        assert response.status_code == 200
        assert response.json()["ok"] is True
        _assert_safe_profile(
            response.json(),
            role_id="predefined_admin_readonly",
            role_name="Read-only administrator",
            trace_allowed=True,
        )
        assert ngfw_mock.routes["login"].call_count == 1
        assert ngfw_mock.routes["whoami"].call_count == 2
        assert binding_pool.get(valid_login_data["login"], valid_login_data["server"]) is None

        assert client.get("/api/users").status_code == 200

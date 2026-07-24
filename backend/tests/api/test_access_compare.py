"""Tests for POST /api/trace/compare and its config flag (docs/API_CONTRACT.md).

The endpoint runs two ordinary read-only traces on one snapshot and returns a
per-stage diff. These tests cover the contract shape, the flag gate (404), the
403 for an insufficient role, per-side subject errors (``compare_side_invalid``),
one snapshot for both sides, secret/source_ip-free logging and the honesty
invariant surfaced through HTTP.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from support import NGFW_SERVER, LiveTestClient

from app.config import get_settings
from app.main import create_app

PASSWORD = "s3cret-Passw0rd"

STAGE_KEYS = [
    "hw_filter",
    "pre_filter",
    "rate_limit",
    "dns",
    "dnat",
    "content_filter",
    "antivirus",
    "firewall",
    "app_control",
    "ips",
    "snat",
    "destination",
]

# A content-filter rule that denies category "cat.blocked" for user.id.1 only.
CF_DENY_RULE = {
    "id": 3,
    "name": "Блокировка запрещённых",
    "access": "deny",
    "categories": ["cat.blocked"],
    "aliases": ["user.id.1"],
    "enabled": True,
}


def _compare(client, a, b, url="example.com", **extra):
    return client.post("/api/trace/compare", json={"url": url, "a": a, "b": b, **extra})


@pytest.fixture
def compare_app(monkeypatch):
    monkeypatch.setenv("STUCK_ENABLE_ACCESS_COMPARE", "true")
    get_settings.cache_clear()
    application = create_app()
    application.state.settings.STUCK_COOKIE_SECURE = False
    try:
        yield application
    finally:
        get_settings.cache_clear()


@pytest.fixture
def disabled_compare_app(monkeypatch):
    monkeypatch.setenv("STUCK_ENABLE_ACCESS_COMPARE", "false")
    get_settings.cache_clear()
    application = create_app()
    application.state.settings.STUCK_COOKIE_SECURE = False
    try:
        yield application
    finally:
        get_settings.cache_clear()


@contextmanager
def _client(app):
    c = LiveTestClient(app)
    try:
        yield c
    finally:
        c.close()


def _login(client, login: str = "admin") -> None:
    resp = client.post("/api/auth/login", json={"login": login, "password": PASSWORD, "server": NGFW_SERVER})
    assert resp.status_code == 200, resp.text


class TestGateAndAuth:
    def test_requires_authentication(self, client: TestClient):
        resp = _compare(client, {}, {})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"

    def test_disabled_returns_404(self, disabled_compare_app, ngfw_mock):
        with _client(disabled_compare_app) as c:
            _login(c)
            resp = _compare(c, {}, {})
            assert resp.status_code == 404
            assert resp.json()["error"]["code"] == "not_found"

    def test_health_and_session_report_flag(self, authenticated_client: TestClient):
        assert authenticated_client.get("/api/health").json()["access_compare_enabled"] is True
        assert authenticated_client.get("/api/session").json()["access_compare_enabled"] is True

    def test_insufficient_role_is_403(self, compare_app, ngfw_mock):
        # A trace-forbidden role: the snapshot load refuses, like every other
        # snapshot-loading endpoint.
        ngfw_mock.state["whoami"] = (
            200,
            {
                "login": "firewall-admin",
                "name": "Firewall Admin",
                "role_id": "predefined_firewall_admin",
                "role_name": "Firewall administrator",
                "competence": ["admin_read"],
            },
        )
        with _client(compare_app) as c:
            _login(c, login="firewall-admin")
            resp = _compare(c, {}, {})
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "insufficient_ngfw_permissions"


class TestContractShape:
    def test_full_shape(self, authenticated_client: TestClient):
        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert set(body) >= {
            "binding",
            "target_input",
            "a",
            "b",
            "categories",
            "stages",
            "primary_divergence",
            "divergence_reason",
            "identical_subjects",
            "rules_updated_at",
            "generated_at",
        }
        assert body["binding"] == {"admin": "admin", "server": NGFW_SERVER}
        assert body["target_input"] == {"url": "example.com", "protocol": "any", "dst_port": None}
        # 12 stages in fixed order, each with both sides.
        assert [s["key"] for s in body["stages"]] == STAGE_KEYS
        for s in body["stages"]:
            assert s["classification"] in ("same", "divergent", "incomparable")
            assert s["a"]["key"] == s["key"]
            assert s["b"]["key"] == s["key"]
        # Per-side context/subject shape. user.id.1 has one default active
        # session in the fixtures, so its single source IP is auto-selected.
        assert body["a"]["context"] == {"has_user": True, "has_source_ip": True}
        assert body["a"]["subject"]["user"]["id"] == "user.id.1"
        assert body["b"]["context"] == {"has_user": False, "has_source_ip": False}
        assert body["b"]["subject"]["user"] is None

    def test_missing_url_is_validation_error(self, authenticated_client: TestClient):
        resp = _compare(authenticated_client, {}, {}, url=" ")
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_identical_subjects_empty_diff(self, authenticated_client: TestClient):
        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {"user_id": "user.id.1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["identical_subjects"] is True
        assert body["divergence_reason"] == "identical"
        assert body["primary_divergence"] is None
        assert all(s["classification"] == "same" for s in body["stages"])

    def test_block_vs_pass_divergence_through_http(self, authenticated_client: TestClient, ngfw_mock):
        # user.id.1 is denied the category at content_filter; the anonymous side
        # is not user-scoped and is not blocked there.
        ngfw_mock.state["cf_rules"] = (200, [CF_DENY_RULE])
        ngfw_mock.state["categorize"] = (200, {"all": ["cat.blocked"], "sky": [], "normalizedUrl": "rts.rs"})

        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {}, url="rts.rs")
        assert resp.status_code == 200
        body = resp.json()
        assert body["primary_divergence"] == "content_filter"
        assert body["divergence_reason"] == "diverged"
        cf = next(s for s in body["stages"] if s["key"] == "content_filter")
        assert cf["classification"] == "divergent"
        assert cf["blocking_side"] == "a"
        assert body["a"]["summary"]["verdict"] == "blocked"


class TestPerSideErrors:
    def test_unknown_user_side_b(self, authenticated_client: TestClient):
        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {"user_id": "no.such"})
        assert resp.status_code == 400
        err = resp.json()["error"]
        assert err["code"] == "compare_side_invalid"
        assert err["details"]["side"] == "b"
        assert err["details"]["reason"] == "unknown_user"
        assert err["details"]["user_id"] == "no.such"

    def test_invalid_source_ip_side_a(self, authenticated_client: TestClient):
        resp = _compare(authenticated_client, {"source_ip": "not-an-ip"}, {})
        assert resp.status_code == 400
        err = resp.json()["error"]
        assert err["code"] == "compare_side_invalid"
        assert err["details"]["side"] == "a"
        assert err["details"]["reason"] == "invalid_source_ip"

    def test_multiple_source_ips_side_a(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["auth_sessions"] = (
            200,
            [
                {"id": "s1", "user_object_id": "user.id.1", "subnet": "192.0.2.10/32"},
                {"id": "s2", "user_object_id": "user.id.1", "subnet": "192.0.2.11/32"},
            ],
        )
        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {})
        assert resp.status_code == 400
        err = resp.json()["error"]
        assert err["details"]["side"] == "a"
        assert err["details"]["reason"] == "multiple_source_ips"
        assert err["details"]["source_ips"] == ["192.0.2.10", "192.0.2.11"]

    def test_source_ip_not_assigned_side_b(self, authenticated_client: TestClient, ngfw_mock):
        # Backend does not trust the client IP: it must belong to the user.
        resp = _compare(
            authenticated_client,
            {"user_id": "user.id.1"},
            {"user_id": "user.id.1", "source_ip": "203.0.113.99"},
        )
        assert resp.status_code == 400
        err = resp.json()["error"]
        assert err["details"]["side"] == "b"
        assert err["details"]["reason"] == "source_ip_not_assigned"
        assert err["details"]["source_ip"] == "203.0.113.99"

    def test_zero_ip_side_is_valid_identity_only(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["auth_sessions"] = (200, [])
        ngfw_mock.state["auth_rules"] = (200, [])
        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {})
        assert resp.status_code == 200
        assert resp.json()["a"]["context"]["has_source_ip"] is False
        assert resp.json()["a"]["subject"]["source_ip"] is None


class TestSnapshotAndLogging:
    def test_single_snapshot_load_for_both_sides(self, authenticated_client: TestClient, ngfw_mock):
        # A fresh authenticated client has not loaded a snapshot yet. One compare
        # must load the snapshot exactly once (users read once) despite two sides.
        before = ngfw_mock.routes["users"].call_count
        resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {"user_id": "user.id.2"})
        assert resp.status_code == 200
        assert ngfw_mock.routes["users"].call_count == before + 1
        # Categorization (a target fact) is computed once, not per side.
        assert ngfw_mock.routes["categorize"].call_count == 1

    def test_response_has_no_secret_or_source_ip_in_log(self, authenticated_client: TestClient, ngfw_mock, caplog):
        import logging

        ngfw_mock.state["auth_sessions"] = (
            200,
            [{"id": "s1", "user_object_id": "user.id.1", "subnet": "192.0.2.10/32"}],
        )
        with caplog.at_level(logging.INFO, logger="stuck.compare"):
            resp = _compare(authenticated_client, {"user_id": "user.id.1"}, {})
        assert resp.status_code == 200
        # The chosen source_ip must not appear in the compare log line.
        compare_records = [r.getMessage() for r in caplog.records if r.name == "stuck.compare"]
        assert compare_records
        for message in compare_records:
            assert "192.0.2.10" not in message
            assert "s3cret" not in message

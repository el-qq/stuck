"""Tests for the rule-snapshot endpoints (app/api/snapshots.py).

docs/API_CONTRACT.md + docs/source/snapshots.md (развилка f): the config gate,
the trace-access requirement, pair isolation, list/create/delete, the shared
per-pair limit, the import endpoint's HTTP-visible errors and the diff endpoint
with its full/anonymized comparison modes.
"""

from __future__ import annotations

from contextlib import contextmanager

from conftest import NGFW_SERVER, LiveTestClient
from fastapi.testclient import TestClient

from app.config import get_settings
from app.domain.snapshots import importer as snapshot_import
from app.main import create_app

PASSWORD = "s3cret-Passw0rd"

FIREWALL_RULE = {"id": "fw.rule.1", "action": "drop", "enabled": True, "comment": "block lab"}

INSUFFICIENT_WHOAMI = {
    "login": "admin",
    "name": "Firewall-only Admin",
    "role_id": "predefined_firewall_admin",
    "role_name": "Firewall administrator",
    "competence": ["firewall"],
}

ALL_ENDPOINTS = (
    ("get", "/api/rules/snapshots", None),
    ("post", "/api/rules/snapshots", {}),
    ("post", "/api/rules/snapshots/import", {"export": {}}),
    ("delete", "/api/rules/snapshots/some-id", None),
    ("get", "/api/rules/snapshots/diff?a=current&b=current", None),
)


def _login(client, login: str = "admin", server: str = NGFW_SERVER) -> None:
    resp = client.post("/api/auth/login", json={"login": login, "password": PASSWORD, "server": server})
    assert resp.status_code == 200, resp.text


def _request(client, method: str, url: str, body):
    if method == "get":
        return client.get(url)
    if method == "delete":
        return client._client.delete(url)  # LiveTestClient exposes get/post only
    return client.post(url, json=body)


def _delete(client, url: str):
    return client._client.delete(url)


@contextmanager
def _app_with_env(monkeypatch, **env: str):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
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


def _create(client, comment=None, refresh=False):
    body = {}
    if comment is not None:
        body["comment"] = comment
    if refresh:
        body["refresh"] = True
    resp = client.post("/api/rules/snapshots", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()["snapshot"]


def _export_doc(client) -> dict:
    resp = client.get("/api/rules/export")
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- Gate and flags ----------------------------------------------------------


class TestGate:
    def test_disabled_answers_404_on_every_endpoint(self, monkeypatch, ngfw_mock):
        with _app_with_env(monkeypatch, STUCK_ENABLE_RULE_SNAPSHOTS="false") as app, _client(app) as client:
            _login(client)
            for method, url, body in ALL_ENDPOINTS:
                resp = _request(client, method, url, body)
                assert resp.status_code == 404, (method, url, resp.text)
                assert resp.json()["error"]["code"] == "not_found"

    def test_flag_true_by_default_in_health_and_session(self, authenticated_client: TestClient):
        assert authenticated_client.get("/api/health").json()["rule_snapshots_enabled"] is True
        assert authenticated_client.get("/api/session").json()["rule_snapshots_enabled"] is True

    def test_flag_false_when_disabled(self, monkeypatch, ngfw_mock):
        with _app_with_env(monkeypatch, STUCK_ENABLE_RULE_SNAPSHOTS="false") as app, _client(app) as client:
            _login(client)
            assert client.get("/api/health").json()["rule_snapshots_enabled"] is False
            assert client.get("/api/session").json()["rule_snapshots_enabled"] is False

    def test_requires_authentication(self, client: TestClient):
        resp = client.get("/api/rules/snapshots")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"

    def test_insufficient_role_gets_403_everywhere(self, client: TestClient, ngfw_mock):
        ngfw_mock.state["whoami"] = (200, INSUFFICIENT_WHOAMI)
        _login(client)
        for method, url, body in ALL_ENDPOINTS:
            resp = _request(client, method, url, body)
            assert resp.status_code == 403, (method, url, resp.text)
            assert resp.json()["error"]["code"] == "insufficient_ngfw_permissions"


# --- List / create / delete --------------------------------------------------


class TestListCreateDelete:
    def test_empty_list_shape(self, authenticated_client: TestClient):
        body = authenticated_client.get("/api/rules/snapshots").json()
        assert body == {
            "binding": {"admin": "admin", "server": NGFW_SERVER},
            "limit": 10,
            "snapshots": [],
        }

    def test_create_returns_descriptor_and_lists_it(self, authenticated_client: TestClient, ngfw_mock):
        created = _create(authenticated_client, comment="  before change  ")
        assert created["source"] == "manual"
        assert created["comment"] == "before change"  # trimmed
        assert isinstance(created["counts"], dict) and created["counts"]["users"] == 2
        assert set(created) == {"id", "created_at", "rules_updated_at", "comment", "source", "counts"}

        listed = authenticated_client.get("/api/rules/snapshots").json()["snapshots"]
        assert [s["id"] for s in listed] == [created["id"]]

    def test_create_lazily_loads_snapshot(self, authenticated_client: TestClient, ngfw_mock):
        assert ngfw_mock.routes["users"].call_count == 0
        _create(authenticated_client)
        assert ngfw_mock.routes["users"].call_count == 1
        # A second create reuses the pooled snapshot: no new NGFW pull.
        _create(authenticated_client)
        assert ngfw_mock.routes["users"].call_count == 1

    def test_create_with_refresh_repulls(self, authenticated_client: TestClient, ngfw_mock):
        _create(authenticated_client)
        calls = ngfw_mock.routes["users"].call_count
        _create(authenticated_client, refresh=True)
        assert ngfw_mock.routes["users"].call_count == calls + 1

    def test_overlong_comment_is_validation_error(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/rules/snapshots", json={"comment": "x" * 201})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_limit_is_409_with_details(self, monkeypatch, ngfw_mock):
        with _app_with_env(monkeypatch, STUCK_SNAPSHOT_LIMIT_PER_BINDING="2") as app, _client(app) as client:
            _login(client)
            _create(client)
            _create(client)
            resp = client.post("/api/rules/snapshots", json={})
            assert resp.status_code == 409
            assert resp.json()["error"]["code"] == "snapshot_limit_reached"
            assert resp.json()["error"]["details"] == {"limit": 2}
            assert client.get("/api/rules/snapshots").json()["limit"] == 2

    def test_delete_then_404_on_repeat(self, authenticated_client: TestClient, ngfw_mock):
        created = _create(authenticated_client)
        resp = _delete(authenticated_client, f"/api/rules/snapshots/{created['id']}")
        assert resp.status_code == 200 and resp.json() == {"ok": True}
        resp = _delete(authenticated_client, f"/api/rules/snapshots/{created['id']}")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"

    def test_unknown_id_404(self, authenticated_client: TestClient):
        assert _delete(authenticated_client, "/api/rules/snapshots/nope").status_code == 404


# --- Pair isolation ----------------------------------------------------------


class TestIsolation:
    def test_other_admins_snapshots_are_invisible(self, app, ngfw_mock):
        with _client(app) as client_a, _client(app) as client_b:
            whoami_a = {**INSUFFICIENT_WHOAMI, "login": "adminA", "role_id": "predefined_admin_readonly"}
            whoami_b = {**INSUFFICIENT_WHOAMI, "login": "adminB", "role_id": "predefined_admin_readonly"}
            ngfw_mock.state["whoami"] = (200, whoami_a)
            _login(client_a, login="adminA")
            created = _create(client_a, comment="a's snapshot")

            ngfw_mock.state["whoami"] = (200, whoami_b)
            _login(client_b, login="adminB")

            assert client_b.get("/api/rules/snapshots").json()["snapshots"] == []
            # B can neither delete nor diff A's snapshot id: it is 404 for B.
            assert _delete(client_b, f"/api/rules/snapshots/{created['id']}").status_code == 404
            diff = client_b.get(f"/api/rules/snapshots/diff?a={created['id']}&b=current")
            assert diff.status_code == 404
            # A still has it.
            assert [s["comment"] for s in client_a.get("/api/rules/snapshots").json()["snapshots"]] == ["a's snapshot"]

    def test_snapshots_survive_logout(self, app, ngfw_mock):
        with _client(app) as client:
            _login(client)
            created = _create(client)
            assert client.post("/api/auth/logout").status_code == 200
            _login(client)
            listed = client.get("/api/rules/snapshots").json()["snapshots"]
            assert [s["id"] for s in listed] == [created["id"]]


# --- Import ------------------------------------------------------------------


class TestImport:
    def test_import_own_export(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": doc, "comment": "prod copy"})
        assert resp.status_code == 200, resp.text
        snapshot = resp.json()["snapshot"]
        assert snapshot["source"] == "imported"
        assert snapshot["comment"] == "prod copy"
        assert snapshot["server"] == NGFW_SERVER
        assert snapshot["foreign_server"] is False
        assert snapshot["exported_at"] == doc["exported_at"]
        assert snapshot["rules_updated_at"] == doc["rules_updated_at"]
        # It participates in the list like any other snapshot.
        listed = authenticated_client.get("/api/rules/snapshots").json()["snapshots"]
        assert [s["source"] for s in listed] == ["imported"]

    def test_import_foreign_server_is_flagged(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        doc["binding"]["server"] = "10.99.99.99"
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": doc})
        assert resp.status_code == 200
        assert resp.json()["snapshot"]["foreign_server"] is True

    def test_import_export_as_string_body_field(self, authenticated_client: TestClient, ngfw_mock):
        """The client may pass the file body verbatim as a string."""
        raw = authenticated_client.get("/api/rules/export").text
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": raw})
        assert resp.status_code == 200
        assert resp.json()["snapshot"]["source"] == "imported"

    def test_imported_file_name_is_a_safe_basename_and_diff_side_metadata(
        self, authenticated_client: TestClient, ngfw_mock
    ):
        doc = _export_doc(authenticated_client)
        resp = authenticated_client.post(
            "/api/rules/snapshots/import",
            json={"export": doc, "file_name": r"C:\\Users\\operator\\rules-before-change.json"},
        )
        assert resp.status_code == 200, resp.text
        imported = resp.json()["snapshot"]
        assert imported["file_name"] == "rules-before-change.json"

        listed = authenticated_client.get("/api/rules/snapshots").json()["snapshots"]
        assert listed[0]["file_name"] == "rules-before-change.json"

        diff = authenticated_client.get(f"/api/rules/snapshots/diff?a={imported['id']}&b=current").json()
        assert diff["a"]["file_name"] == "rules-before-change.json"

    def test_import_file_name_validation(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        for file_name in (42, "", "a" * 201, "rules\n.json"):
            resp = authenticated_client.post(
                "/api/rules/snapshots/import", json={"export": doc, "file_name": file_name}
            )
            assert resp.status_code == 400
            assert resp.json()["error"]["code"] == "validation_error"

    def test_truncated_file_string_is_json_reason(self, authenticated_client: TestClient, ngfw_mock):
        raw = authenticated_client.get("/api/rules/export").text[:100]
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": raw})
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["code"] == "snapshot_import_invalid"
        assert error["details"] == {"reason": "json"}

    def test_non_json_body_is_json_reason(self, authenticated_client: TestClient):
        resp = authenticated_client._client.post(
            "/api/rules/snapshots/import",
            content=b'{"export": {tru',
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["details"] == {"reason": "json"}

    def test_unsupported_format(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        doc["format"] = "stuck.rules/v1"
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": doc})
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["code"] == "snapshot_import_unsupported_format"
        assert error["details"] == {"format": "stuck.rules/v1"}

    def test_filtered_export_rejected(self, authenticated_client: TestClient, ngfw_mock):
        doc = authenticated_client.get("/api/rules/export", params={"user_id": "user.id.1"}).json()
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": doc})
        assert resp.status_code == 400
        assert resp.json()["error"]["details"] == {"reason": "filtered_export"}

    def test_oversized_body_is_413(self, authenticated_client: TestClient, ngfw_mock, monkeypatch):
        monkeypatch.setattr(snapshot_import, "IMPORT_MAX_BYTES", 64)
        resp = authenticated_client.post("/api/rules/snapshots/import", json={"export": {"pad": "x" * 100}})
        assert resp.status_code == 413
        error = resp.json()["error"]
        assert error["code"] == "snapshot_import_too_large"
        assert error["details"] == {"limit_bytes": 64}

    def test_import_counts_against_shared_limit(self, monkeypatch, ngfw_mock):
        with _app_with_env(monkeypatch, STUCK_SNAPSHOT_LIMIT_PER_BINDING="1") as app, _client(app) as client:
            _login(client)
            doc = _export_doc(client)
            assert client.post("/api/rules/snapshots/import", json={"export": doc}).status_code == 200
            resp = client.post("/api/rules/snapshots/import", json={"export": doc})
            assert resp.status_code == 409
            assert resp.json()["error"]["code"] == "snapshot_limit_reached"

    def test_duplicate_import_is_not_an_error(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        assert authenticated_client.post("/api/rules/snapshots/import", json={"export": doc}).status_code == 200
        assert authenticated_client.post("/api/rules/snapshots/import", json={"export": doc}).status_code == 200
        assert len(authenticated_client.get("/api/rules/snapshots").json()["snapshots"]) == 2

    def test_import_never_calls_ngfw(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        calls_before = {key: route.call_count for key, route in ngfw_mock.routes.items()}
        authenticated_client.post("/api/rules/snapshots/import", json={"export": doc})
        calls_after = {key: route.call_count for key, route in ngfw_mock.routes.items()}
        assert calls_after == calls_before


# --- Diff --------------------------------------------------------------------


class TestDiff:
    def test_current_vs_current_is_empty_full_diff(self, authenticated_client: TestClient, ngfw_mock):
        resp = authenticated_client.get("/api/rules/snapshots/diff?a=current&b=current")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["binding"] == {"admin": "admin", "server": NGFW_SERVER}
        assert body["a"]["id"] == "current" and body["a"]["source"] == "current"
        assert body["b"]["id"] == "current"
        assert body["comparison_mode"] == "full"
        assert body["tables"] == [] and body["states"] == []
        assert body["summary"] == {
            "added": 0,
            "removed": 0,
            "changed": 0,
            "moved": 0,
            "states_changed": 0,
            "tables_changed": 0,
        }
        # `current` lazily loaded the snapshot (none was pooled before).
        assert ngfw_mock.routes["users"].call_count == 1

    def test_saved_vs_current_reports_changes(self, authenticated_client: TestClient, ngfw_mock):
        created = _create(authenticated_client)  # snapshot with no fw rules

        # NGFW config changes: one forward rule appears, CF gets disabled.
        ngfw_mock.state["fw_forward"] = (200, [FIREWALL_RULE])
        ngfw_mock.state["cf_state"] = (200, {"enabled": False})
        assert authenticated_client.post("/api/rules/refresh").status_code == 200

        body = authenticated_client.get(f"/api/rules/snapshots/diff?a={created['id']}&b=current").json()
        assert body["a"]["id"] == created["id"] and body["a"]["source"] == "manual"
        assert body["comparison_mode"] == "full"
        (table,) = [t for t in body["tables"] if t["table"] == "fw_forward"]
        assert [e["kind"] for e in table["entries"]] == ["added"]
        assert table["entries"][0]["id"] == "fw.rule.1"
        assert {"key": "cf_state.enabled", "from": True, "to": False} in body["states"]
        assert body["summary"]["added"] == 1
        assert body["summary"]["states_changed"] == 1

    def test_same_saved_snapshot_both_sides(self, authenticated_client: TestClient, ngfw_mock):
        created = _create(authenticated_client)
        body = authenticated_client.get(f"/api/rules/snapshots/diff?a={created['id']}&b={created['id']}").json()
        assert body["tables"] == [] and body["states"] == []

    def test_unknown_id_404(self, authenticated_client: TestClient, ngfw_mock):
        resp = authenticated_client.get("/api/rules/snapshots/diff?a=nope&b=current")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"

    def test_missing_params_are_validation_error(self, authenticated_client: TestClient):
        resp = authenticated_client.get("/api/rules/snapshots/diff")
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_imported_side_forces_anonymized_mode(self, authenticated_client: TestClient, ngfw_mock):
        doc = _export_doc(authenticated_client)
        imported = authenticated_client.post("/api/rules/snapshots/import", json={"export": doc}).json()["snapshot"]

        body = authenticated_client.get(f"/api/rules/snapshots/diff?a={imported['id']}&b=current").json()
        assert body["comparison_mode"] == "anonymized"
        assert body["a"]["source"] == "imported"
        assert body["a"]["foreign_server"] is False
        # Export of the same live snapshot → no differences in anonymized mode
        # (the round-trip comparability invariant, h.2).
        assert body["tables"] == [] and body["states"] == []

    def test_diff_response_carries_no_secrets(self, authenticated_client: TestClient, ngfw_mock):
        created = _create(authenticated_client)
        ngfw_mock.state["fw_forward"] = (200, [FIREWALL_RULE])
        authenticated_client.post("/api/rules/refresh")
        raw = authenticated_client.get(f"/api/rules/snapshots/diff?a={created['id']}&b=current").text
        assert PASSWORD not in raw
        stuck_session = authenticated_client.cookies.get("stuck_session")
        assert stuck_session and stuck_session not in raw

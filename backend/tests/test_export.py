"""Tests for GET /api/rules/export (docs/API_CONTRACT.md).

Covers the config gate (enabled by default and explicitly disabled), the
feature flag surfaced in session/health, the full-snapshot export, the
?user_id slice, ?refresh re-pull,
the "no secrets" invariant, the HARD isolation invariant (session B never sees
binding A), Content-Disposition, and goal (b): the exported JSON round-trips
back into a RulesSnapshot that drives the trace engine (usable as a fixture).
"""

from __future__ import annotations

from contextlib import contextmanager

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import DEFAULT_USERS, LiveTestClient, NGFW_SERVER, NGFW_SESSION_VALUE

from app.config import get_settings
from app.domain import trace_engine
from app.domain.binding_pool import RulesSnapshot
from app.main import create_app
from app.ngfw import schemas as S
from app.ngfw.client import NgfwClient

PASSWORD = "s3cret-Passw0rd"


def _whoami(login: str) -> dict[str, object]:
    """Minimal valid canonical administrator profile for a mocked NGFW."""

    return {
        "login": login,
        "name": f"{login} display name",
        "role_id": "predefined_admin_readonly",
        "role_name": "Read-only administrator",
        "competence": ["admin_read"],
    }


# A content-filter rule denying category "cat.blocked" for user.id.1 only.
CF_DENY_RULE = {
    "id": 3,
    "name": "Block prohibited",
    "access": "deny",
    "categories": ["cat.blocked"],
    "aliases": ["user.id.1"],
    "enabled": True,
}
# A second CF rule scoped to a DIFFERENT user — must drop out of a user.id.1 slice.
CF_OTHER_RULE = {
    "id": 4,
    "name": "Something for jane",
    "access": "deny",
    "categories": ["cat.other"],
    "aliases": ["user.id.2"],
    "enabled": True,
}


# --- app / client helpers ----------------------------------------------------


@pytest.fixture
def export_app(monkeypatch):
    """A fresh app with STUCK_ENABLE_RULES_EXPORT=true (cache cleared around it)."""
    monkeypatch.setenv("STUCK_ENABLE_RULES_EXPORT", "true")
    get_settings.cache_clear()
    application = create_app()
    # Tests reach the app over loopback HTTP; the shipped Docker profile keeps
    # STUCK_COOKIE_SECURE=true (mirrors conftest's default `app` fixture).
    application.state.settings.STUCK_COOKIE_SECURE = False
    try:
        yield application
    finally:
        # Never leak the enabled flag into other tests' cached settings.
        get_settings.cache_clear()


@pytest.fixture
def disabled_export_app(monkeypatch):
    """A fresh app with rules export explicitly disabled."""
    monkeypatch.setenv("STUCK_ENABLE_RULES_EXPORT", "false")
    get_settings.cache_clear()
    application = create_app()
    application.state.settings.STUCK_COOKIE_SECURE = False
    try:
        yield application
    finally:
        get_settings.cache_clear()


@pytest.fixture
def disabled_export_client(disabled_export_app):
    test_client = LiveTestClient(disabled_export_app)
    try:
        yield test_client
    finally:
        test_client.close()


@pytest.fixture
def export_client(export_app):
    test_client = LiveTestClient(export_app)
    try:
        yield test_client
    finally:
        test_client.close()


def _login(client, login: str = "admin", server: str = NGFW_SERVER) -> None:
    resp = client.post("/api/auth/login", json={"login": login, "password": PASSWORD, "server": server})
    assert resp.status_code == 200, resp.text


@contextmanager
def _client(app):
    """A managed LiveTestClient (auto-closed) for tests needing several clients."""
    c = LiveTestClient(app)
    try:
        yield c
    finally:
        c.close()


def _register_data_endpoints(router, base: str) -> None:
    """Register a minimal valid NGFW data endpoint set for an extra server host."""
    static = {
        "/user_backend/users": [],
        "/aliases/all": [],
        "/firewall/rules/forward": [],
        "/firewall/rules/input": [],
        "/firewall/rules/dnat": [],
        "/firewall/rules/snat": [],
        "/firewall/settings": {"automatic_snat_enabled": False},
        "/l2manager/connection_state": [],
        "/firewall/state": {"enabled": True},
        "/content-filter/state": {"enabled": True},
        "/content-filter/rules": [],
        "/content-filter/categories": [],
        "/api/shaper/state": {"enabled": True},
        "/api/shaper/rules/before": [],
        "/api/shaper/rules": [],
        "/api/shaper/rules/after": [],
        "/ips/state": {"enabled": True},
        "/ips/bypass": [],
        "/av_backend/state": {"enabled": True},
        "/av_backend/profiles/default": {"profile_id": "av_profile.id.default"},
        "/av_backend/profiles": [{"id": "default", "enabled": True}],
    }
    for path, body in static.items():
        router.get(f"{base}{path}").mock(return_value=httpx.Response(200, json=body))
    router.get(f"{base}/firewall/rules/drop_rules/export").mock(
        return_value=httpx.Response(
            200,
            text='"Rule type";"Protocol";"Source IP-address";"Source port";'
            '"Destination IP-address";"Destination port";"TCP-flags";'
            '"TCP-flags to blocking";"Packet length, bytes";"Comment";"Enabled"\r\n',
        )
    )


@pytest.fixture
def export_authed(export_client, ngfw_mock):
    """Authenticated client on the export-enabled app."""
    _login(export_client)
    return export_client


# --- 1. Gate: enabled by default, with an explicit off switch ---------------


class TestExportGate:
    def test_enabled_by_default(self, authenticated_client: TestClient):
        resp = authenticated_client.get("/api/rules/export")
        assert resp.status_code == 200

    def test_session_reports_flag_true_by_default(self, authenticated_client: TestClient):
        resp = authenticated_client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json()["rules_export_enabled"] is True

    def test_health_reports_flag_true_by_default(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["rules_export_enabled"] is True

    def test_explicitly_disabled_returns_404(self, disabled_export_client: TestClient, ngfw_mock):
        """Explicit off switch: the endpoint behaves as if it does not exist."""
        _login(disabled_export_client)
        resp = disabled_export_client.get("/api/rules/export")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"

    def test_explicitly_disabled_flags_false(self, disabled_export_client: TestClient, ngfw_mock):
        _login(disabled_export_client)
        resp = disabled_export_client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json()["rules_export_enabled"] is False
        health = disabled_export_client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["rules_export_enabled"] is False

    def test_disabled_export_requires_no_disclosure_even_authed(self, disabled_export_client: TestClient, ngfw_mock):
        """404 whether or not user_id/refresh params are supplied."""
        _login(disabled_export_client)
        assert disabled_export_client.get("/api/rules/export", params={"user_id": "user.id.1"}).status_code == 404
        assert disabled_export_client.get("/api/rules/export", params={"refresh": "true"}).status_code == 404

    def test_export_requires_authentication_when_enabled(self, export_client: TestClient):
        """Enabled but no session → still protected (401, not 404)."""
        resp = export_client.get("/api/rules/export")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"


# --- 2. Enabled: full snapshot ----------------------------------------------


class TestExportFullSnapshot:
    def test_flag_true_when_enabled(self, export_authed: TestClient):
        assert export_authed.get("/api/session").json()["rules_export_enabled"] is True

    def test_health_flag_true_when_enabled(self, export_client: TestClient):
        assert export_client.get("/api/health").json()["rules_export_enabled"] is True

    def test_full_export_shape(self, export_authed: TestClient):
        resp = export_authed.get("/api/rules/export")

        assert resp.status_code == 200
        body = resp.json()

        # Binding comes from the session.
        assert body["binding"] == {"admin": "admin", "server": NGFW_SERVER}
        assert body["filtered_by_user_id"] is None
        assert isinstance(body["rules_updated_at"], str)
        assert isinstance(body["exported_at"], str)

        snap = body["snapshot"]
        for key in (
            "users",
            "aliases",
            "firewall_forward",
            "firewall_input",
            "firewall_state",
            "content_filter",
            "ips_state",
            "ips_bypass",
            "objects",
            "av_profile",
        ):
            assert key in snap, f"missing snapshot.{key}"
        # content_filter is a bundle {state, rules, categories}.
        assert set(snap["content_filter"]) >= {"state", "rules", "categories"}
        assert snap["av_profile"] == {"enabled": True}
        assert len(snap["users"]) == len(DEFAULT_USERS)

    def test_content_disposition_header(self, export_authed: TestClient):
        resp = export_authed.get("/api/rules/export")

        cd = resp.headers.get("Content-Disposition")
        assert cd is not None
        assert "attachment" in cd
        assert f'filename="rules-{NGFW_SERVER}-' in cd
        assert cd.endswith('.json"')


# --- 3. No secrets -----------------------------------------------------------


class TestExportNoSecrets:
    def test_export_body_contains_no_secrets(self, export_authed: TestClient):
        resp = export_authed.get("/api/rules/export")
        assert resp.status_code == 200

        raw = resp.text  # serialized JSON exactly as sent to the browser
        assert PASSWORD not in raw
        assert NGFW_SESSION_VALUE not in raw
        # Session cookie value must not appear either.
        stuck_session = export_authed.cookies.get("stuck_session")
        assert stuck_session
        assert stuck_session not in raw

        # No secret-looking keys anywhere in the structure.
        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    low = str(k).lower()
                    assert "password" not in low
                    assert "cookie" not in low
                    assert "stuck_session" not in low
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(resp.json())


# --- 4. ?user_id slice -------------------------------------------------------


class TestExportUserFilter:
    def test_user_filter_narrows_snapshot(self, export_client: TestClient, ngfw_mock):
        ngfw_mock.state["cf_rules"] = (200, [CF_DENY_RULE, CF_OTHER_RULE])
        _login(export_client)

        full = export_client.get("/api/rules/export").json()["snapshot"]
        sliced_resp = export_client.get("/api/rules/export", params={"user_id": "user.id.1"})

        assert sliced_resp.status_code == 200
        body = sliced_resp.json()
        assert body["filtered_by_user_id"] == "user.id.1"
        sliced = body["snapshot"]

        # Every sliced rule list is <= the full one.
        for key in ("firewall_forward", "firewall_input", "content_filter", "ips_bypass"):
            full_len = len(full["content_filter"]["rules"]) if key == "content_filter" else len(full[key])
            sliced_len = len(sliced["content_filter"]["rules"]) if key == "content_filter" else len(sliced[key])
            assert sliced_len <= full_len

        # Content filter is strictly reduced: only user.id.1's rule survives.
        cf_ids = [r["id"] for r in sliced["content_filter"]["rules"]]
        assert cf_ids == ["3"]
        # Users collapses to just the filtered user.
        assert [u["id"] for u in sliced["users"]] == ["user.id.1"]

    def test_unknown_user_id_not_found(self, export_authed: TestClient):
        resp = export_authed.get("/api/rules/export", params={"user_id": "no.such.user"})
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"


# --- 5. ?refresh re-pull -----------------------------------------------------


class TestExportRefresh:
    def test_refresh_repulls_from_ngfw(self, export_client: TestClient, ngfw_mock):
        _login(export_client)
        # First export pools the snapshot (one users call so far).
        export_client.get("/api/rules/export")
        calls_before = ngfw_mock.routes["users"].call_count

        # A plain export must NOT hit NGFW again (served from the pool).
        export_client.get("/api/rules/export")
        assert ngfw_mock.routes["users"].call_count == calls_before

        # ?refresh=true forces a re-pull.
        resp = export_client.get("/api/rules/export", params={"refresh": "true"})
        assert resp.status_code == 200
        assert ngfw_mock.routes["users"].call_count > calls_before

    def test_refresh_with_expired_ngfw_cookie(self, export_client: TestClient, ngfw_mock):
        _login(export_client)
        export_client.get("/api/rules/export")  # pool it

        ngfw_mock.state["users"] = (401, {"message": "unauthorized"})
        resp = export_client.get("/api/rules/export", params={"refresh": "true"})

        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "session_expired"


# --- 6. HARD isolation invariant (FR-12.5) ----------------------------------


class TestExportIsolation:
    def test_session_b_never_sees_binding_a(self, export_app, ngfw_mock):
        """Two admins on the same server: export always reflects the caller's binding."""
        with _client(export_app) as client_a, _client(export_app) as client_b:
            # Admin A loads a 2-user snapshot.
            ngfw_mock.state["whoami"] = (200, _whoami("adminA"))
            _login(client_a, login="adminA")
            assert len(client_a.get("/api/rules/export").json()["snapshot"]["users"]) == 2

            # NGFW now has 3 users; admin B loads ITS OWN snapshot.
            ngfw_mock.state["users"] = (
                200,
                DEFAULT_USERS + [{"id": "user.id.3", "name": "New", "login": "new"}],
            )
            ngfw_mock.state["whoami"] = (200, _whoami("adminB"))
            _login(client_b, login="adminB")

            export_a = client_a.get("/api/rules/export").json()
            export_b = client_b.get("/api/rules/export").json()

        # Each session only ever sees its own binding.
        assert export_a["binding"]["admin"] == "adminA"
        assert export_b["binding"]["admin"] == "adminB"
        assert len(export_a["snapshot"]["users"]) == 2  # A's binding, untouched
        assert len(export_b["snapshot"]["users"]) == 3  # B's own binding

    def test_query_params_cannot_reach_another_binding(self, export_app, ngfw_mock):
        """No request param overrides the binding (admin/server come from the session)."""
        with _client(export_app) as client_a, _client(export_app) as client_b:
            ngfw_mock.state["whoami"] = (200, _whoami("adminA"))
            _login(client_a, login="adminA")
            client_a.get("/api/rules/export")  # binding A exists in the pool
            ngfw_mock.state["whoami"] = (200, _whoami("adminB"))
            _login(client_b, login="adminB")

            # Even hostile-looking params only ever act within B's binding.
            for params in ({"user_id": "user.id.1"}, {"refresh": "true"}):
                body = client_b.get("/api/rules/export", params=params).json()
                if "binding" in body:  # user_id.1 exists, so this is a 200 body
                    assert body["binding"]["admin"] == "adminB"

    def test_isolation_by_server(self, export_app, ngfw_mock):
        """Same admin, different server = different binding."""
        # Mock NGFW login + the full data endpoint set on a second server host.
        base2 = "https://10.0.0.2:8443"
        ngfw_mock.router.post(f"{base2}/web/auth/login").mock(
            return_value=httpx.Response(
                200,
                json={"success": True},
                headers=[("set-cookie", "insecure-ideco-session=tok2; Path=/")],
            )
        )
        ngfw_mock.router.get(f"{base2}/web/whoami").mock(return_value=httpx.Response(200, json=_whoami("admin")))
        _register_data_endpoints(ngfw_mock.router, base2)

        with _client(export_app) as client1, _client(export_app) as client2:
            ngfw_mock.state["whoami"] = (200, _whoami("admin"))
            _login(client1, login="admin", server=NGFW_SERVER)
            assert client1.get("/api/rules/export").json()["binding"]["server"] == NGFW_SERVER

            _login(client2, login="admin", server="10.0.0.2")
            assert client2.get("/api/rules/export").json()["binding"]["server"] == "10.0.0.2"


# --- 8. Goal (b): exported JSON usable as a trace-engine fixture -------------


def _snapshot_from_export(exp_snapshot: dict) -> RulesSnapshot:
    """Round-trip the documented export schema back into a RulesSnapshot.

    Demonstrates that the exported JSON is a faithful, reusable fixture for the
    offline trace engine (the export round-trip invariant in API_CONTRACT.md).
    """
    aliases = {a["id"]: S.Alias.model_validate(a) for a in exp_snapshot["aliases"] if isinstance(a, dict) and "id" in a}
    cf = exp_snapshot["content_filter"]
    speed_limit = exp_snapshot["speed_limit"]
    return RulesSnapshot(
        users=S.parse_list(S.NgfwUser, exp_snapshot["users"], what="users"),
        aliases=aliases,
        fw_forward=S.parse_list(S.FirewallRule, exp_snapshot["firewall_forward"], what="fw"),
        fw_input=S.parse_list(S.FirewallRule, exp_snapshot["firewall_input"], what="fw"),
        fw_pre_filter=S.parse_list(S.PreliminaryRule, exp_snapshot["firewall_pre_filter"], what="pre_filter"),
        fw_dnat=S.parse_list(S.FirewallRule, exp_snapshot["firewall_dnat"], what="dnat"),
        fw_snat=S.parse_list(S.FirewallRule, exp_snapshot["firewall_snat"], what="snat"),
        fw_settings=S.FirewallSettings.model_validate(exp_snapshot["firewall_settings"]),
        ngfw_addresses=list(exp_snapshot["ngfw_addresses"]),
        fw_state=S.StateFlag.model_validate(exp_snapshot["firewall_state"]),
        cf_state=S.StateFlag.model_validate(cf["state"]),
        cf_rules=S.parse_list(S.ContentFilterRule, cf["rules"], what="cf"),
        cf_categories=cf["categories"],
        ips_state=S.StateFlag.model_validate(exp_snapshot["ips_state"]),
        ips_bypass=S.parse_list(S.IpsBypass, exp_snapshot["ips_bypass"], what="ips"),
        av_enabled=bool(exp_snapshot["av_profile"]["enabled"]),
        shaper_state=S.StateFlag.model_validate(speed_limit["state"]),
        shaper_rules=S.parse_list(S.ShaperRule, speed_limit["rules"], what="shaper"),
    )


class TestExportAsFixture:
    @pytest.mark.asyncio
    async def test_exported_rules_drive_the_trace_engine(self, export_client: TestClient, ngfw_mock):
        # A CF deny rule that will block user.id.1 on category cat.blocked.
        ngfw_mock.state["cf_rules"] = (200, [CF_DENY_RULE])
        _login(export_client)

        exported = export_client.get("/api/rules/export").json()
        assert exported["snapshot"]["content_filter"]["rules"][0]["id"] == "3"

        # (b) Reconstruct a RulesSnapshot straight from the exported JSON.
        snap = _snapshot_from_export(exported["snapshot"])
        user = next(u for u in snap.users if str(u.id) == "user.id.1")

        # Run the real trace engine on the reconstructed fixture.
        ngfw_mock.state["categorize"] = (
            200,
            {"all": ["cat.blocked"], "sky": [], "normalizedUrl": "rts.rs"},
        )
        client = NgfwClient(NGFW_SERVER, {"insecure-ideco-session": "x"})
        result = await trace_engine.run_trace(
            snap, client, url="rts.rs", user=user, protocol="tcp", dst_port_override=None
        )

        cf_stage = next(s for s in result["stages"] if s["key"] == "content_filter")
        assert cf_stage["status"] == "block"
        assert cf_stage["detail"]["rule_id"] == "3"
        assert result["summary"]["verdict"] == "blocked"
        assert result["summary"]["blocked_at"] == "content_filter"

    @pytest.mark.asyncio
    async def test_exported_rules_reproduce_live_trace(self, export_client: TestClient, ngfw_mock):
        """The exported fixture reproduces the exact verdict of the live /api/trace."""
        ngfw_mock.state["categorize"] = (
            200,
            {"all": [], "sky": [], "normalizedUrl": "example.com"},
        )
        _login(export_client)

        # The real endpoint's verdict on the live (pooled) snapshot.
        live = export_client.post("/api/trace", json={"url": "example.com"}).json()

        # Reconstruct the same snapshot from the exported JSON and re-run the engine.
        exported = export_client.get("/api/rules/export").json()
        snap = _snapshot_from_export(exported["snapshot"])
        client = NgfwClient(NGFW_SERVER, {"insecure-ideco-session": "x"})
        recon = await trace_engine.run_trace(
            snap, client, url="example.com", user=None, protocol="tcp", dst_port_override=None
        )

        # Same verdict and same per-stage statuses: the export is a faithful fixture.
        assert len(recon["stages"]) == 11
        assert recon["summary"]["verdict"] == live["summary"]["verdict"]
        assert [s["status"] for s in recon["stages"]] == [s["status"] for s in live["stages"]]

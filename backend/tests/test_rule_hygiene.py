"""Tests for rule-hygiene analysis (app/domain/rule_hygiene.py) and its endpoint
GET /api/rules/hygiene (docs/API_CONTRACT.md).

The analyser is a pure function of the snapshot, so most cases build a minimal
RulesSnapshot directly and assert the findings. Endpoint tests cover the config
gate (enabled by default / 404 when disabled) and the happy-path shape.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from conftest import NGFW_SERVER, LiveTestClient
from fastapi.testclient import TestClient

from app.config import get_settings
from app.domain import rule_hygiene
from app.domain.binding_pool import RulesSnapshot
from app.main import create_app
from app.ngfw import schemas as S

PASSWORD = "s3cret-Passw0rd"


# --- helpers -----------------------------------------------------------------


def _rule(
    rid,
    *,
    action="accept",
    enabled=True,
    sources=None,
    destinations=None,
    dst_ports=None,
    protocol="any",
    negate_sources=False,
    comment="",
    **kw,
) -> S.FirewallRule:
    src_blocks = []
    if sources is not None:
        src_blocks = [S.SourceDest(addresses=list(sources), addresses_negate=negate_sources)]
    dst_blocks = []
    if destinations is not None:
        dst_blocks = [S.SourceDest(addresses=list(destinations))]
    return S.FirewallRule(
        id=str(rid),
        action=action,
        enabled=enabled,
        sources=src_blocks,
        destinations=dst_blocks,
        destination_ports=list(dst_ports) if dst_ports is not None else [],
        protocol=protocol,
        comment=comment,
        **kw,
    )


def _snap(fw_forward=None, fw_input=None, **hw) -> RulesSnapshot:
    return RulesSnapshot(
        users=[],
        aliases={},
        fw_forward=list(fw_forward or []),
        fw_input=list(fw_input or []),
        fw_state=S.StateFlag(enabled=True),
        cf_state=S.StateFlag(),
        cf_rules=[],
        cf_categories=None,
        ips_state=S.StateFlag(),
        ips_bypass=[],
        av_enabled=False,
        **hw,
    )


def _kinds(report) -> list[str]:
    return [f["kind"] for f in report["findings"]]


def _by_rule(report, rid):
    return [f for f in report["findings"] if f["rule"]["id"] == str(rid)]


# --- shadow / redundant ------------------------------------------------------


class TestShadowRedundant:
    def test_shadowed_certain_opposing_action(self):
        # A broad accept (10/8) precedes a drop for the same set → the drop is
        # unreachable: shadowed, certain, opposing actions.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"]),
                    _rule(2, action="drop", sources=["10.0.0.0/8"]),
                ]
            )
        )
        found = _by_rule(report, 2)
        assert len(found) == 1
        assert found[0]["kind"] == "shadowed"
        assert found[0]["severity"] == "warning"
        assert found[0]["tier"] == "certain"
        assert found[0]["related"][0]["id"] == "1"
        assert report["summary"]["warning"] == 1

    def test_redundant_same_action(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"]),
                    _rule(2, action="accept", sources=["10.0.0.0/8"]),
                ]
            )
        )
        found = _by_rule(report, 2)
        assert found[0]["kind"] == "redundant"
        assert found[0]["severity"] == "info"

    def test_no_false_positive_when_not_covered(self):
        # A narrower predecessor (10.1/16) does NOT cover a broader rule (10/8).
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.1.0.0/16"]),
                    _rule(2, action="drop", sources=["10.0.0.0/8"]),
                ]
            )
        )
        assert _by_rule(report, 2) == []

    def test_earliest_coverer_only(self):
        # Two predecessors could cover rule 3; only the earliest is attributed.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"]),
                    _rule(2, action="accept", sources=["10.0.0.0/8"]),
                    _rule(3, action="drop", sources=["10.0.0.0/8"]),
                ]
            )
        )
        found = _by_rule(report, 3)
        assert len(found) == 1
        assert found[0]["related"][0]["id"] == "1"

    def test_disabled_predecessor_does_not_shadow(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"], enabled=False),
                    _rule(2, action="drop", sources=["10.0.0.0/8"]),
                ]
            )
        )
        assert _by_rule(report, 2) == []

    def test_disabled_rule_is_never_a_subject(self):
        # A disabled rule cannot match traffic, so hygiene must not report it —
        # neither as shadowed/redundant nor as overly broad / catch-all.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"]),
                    _rule(2, action="drop", sources=["10.0.0.0/8"], enabled=False),
                    _rule(3, action="accept", enabled=False),  # disabled any-any
                    _rule(4, action="drop", sources=["192.168.0.0/16"]),
                ]
            )
        )
        assert _by_rule(report, 2) == []
        assert _by_rule(report, 3) == []
        # And the disabled catch-all does not make rule 4 unreachable.
        assert _kinds(report).count("unreachable_after_any") == 0
        assert _by_rule(report, 4) == []


# --- possible tier (conservative) --------------------------------------------


class TestPossibleTier:
    def test_negated_source_is_opaque_possible(self):
        # A negated address set is opaque: coverage cannot be proven → possible.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"], negate_sources=True),
                    _rule(2, action="drop", sources=["10.0.0.0/8"]),
                ]
            )
        )
        found = _by_rule(report, 2)
        assert len(found) == 1
        assert found[0]["tier"] == "possible"
        assert report["summary"]["possible"] == 1

    def test_narrowing_condition_caps_at_possible(self):
        # The predecessor matches only some traffic (a source-port condition), so
        # it can only *possibly* shadow the later rule.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"], source_ports=["port.https"]),
                    _rule(2, action="drop", sources=["10.0.0.0/8"]),
                ]
            )
        )
        found = _by_rule(report, 2)
        assert found[0]["tier"] == "possible"


# --- dimension coverage ------------------------------------------------------


class TestDimensionCoverage:
    def test_specific_protocol_does_not_cover_another(self):
        # A matches only tcp, B only udp — no coverage, no finding.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"], protocol="tcp"),
                    _rule(2, action="drop", sources=["10.0.0.0/8"], protocol="udp"),
                ]
            )
        )
        assert _by_rule(report, 2) == []

    def test_any_protocol_covers_specific(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.0.0.0/8"]),  # protocol any
                    _rule(2, action="drop", sources=["10.0.0.0/8"], protocol="tcp"),
                ]
            )
        )
        found = _by_rule(report, 2)
        assert len(found) == 1
        assert found[0]["kind"] == "shadowed"
        assert found[0]["tier"] == "certain"

    def test_port_token_superset_covers(self):
        # A references a superset of B's destination-port objects → coverage.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", dst_ports=["port.web", "port.dns"]),
                    _rule(2, action="drop", dst_ports=["port.web"]),
                ]
            )
        )
        found = _by_rule(report, 2)
        assert len(found) == 1
        assert found[0]["tier"] == "certain"

    def test_port_token_subset_does_not_cover(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", dst_ports=["port.web"]),
                    _rule(2, action="drop", dst_ports=["port.web", "port.dns"]),
                ]
            )
        )
        assert _by_rule(report, 2) == []

    def test_multi_block_sources_are_opaque_possible(self):
        # Two AND-combined source blocks cannot be compared with literal tokens
        # → coverage degrades to the "possible" tier, never "certain".
        rule_a = S.FirewallRule(
            id="1",
            action="accept",
            sources=[
                S.SourceDest(addresses=["10.0.0.0/8"]),
                S.SourceDest(addresses=["user.id.1"]),
            ],
        )
        report = rule_hygiene.analyze_snapshot(
            _snap(fw_forward=[rule_a, _rule(2, action="drop", sources=["10.0.0.0/8"])])
        )
        found = _by_rule(report, 2)
        assert len(found) == 1
        assert found[0]["tier"] == "possible"


# --- overly broad / catch-all ------------------------------------------------


class TestBroadAndCatchAll:
    def test_overly_broad_first_rule_is_risk(self):
        # Nothing before the any-any accept → ALL traffic allowed → risk.
        report = rule_hygiene.analyze_snapshot(_snap(fw_forward=[_rule(1, action="accept")]))
        found = [f for f in report["findings"] if f["kind"] == "overly_broad"]
        assert len(found) == 1
        assert found[0]["severity"] == "risk"
        assert report["summary"]["risk"] == 1

    def test_overly_broad_after_drops_is_info(self):
        # The common "deny exceptions, allow the rest" tail is deliberate → info.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="drop", sources=["10.66.0.0/16"]),
                    _rule(2, action="accept"),
                ]
            )
        )
        found = [f for f in report["findings"] if f["kind"] == "overly_broad"]
        assert len(found) == 1
        assert found[0]["severity"] == "info"

    def test_overly_broad_after_accepts_only_is_warning(self):
        # A broad allow with no exception carved out anywhere → warning.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="accept", sources=["10.66.0.0/16"]),
                    _rule(2, action="accept"),
                ]
            )
        )
        found = [f for f in report["findings"] if f["kind"] == "overly_broad"]
        assert len(found) == 1
        assert found[0]["severity"] == "warning"

    def test_overly_broad_ignores_disabled_predecessors(self):
        # A disabled drop before it does not soften the verdict → still risk.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="drop", sources=["10.66.0.0/16"], enabled=False),
                    _rule(2, action="accept"),
                ]
            )
        )
        found = [f for f in report["findings"] if f["kind"] == "overly_broad"]
        assert found[0]["severity"] == "risk"

    def test_catch_all_reports_unreachable_once(self):
        # A universal drop makes everything after it dead: ONE grouped finding,
        # not a shadow finding per rule.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[
                    _rule(1, action="drop"),  # universal catch-all
                    _rule(2, action="accept", sources=["10.0.0.0/8"]),
                    _rule(3, action="accept", sources=["192.168.0.0/16"]),
                ]
            )
        )
        kinds = _kinds(report)
        assert kinds.count("unreachable_after_any") == 1
        assert "shadowed" not in kinds
        finding = next(f for f in report["findings"] if f["kind"] == "unreachable_after_any")
        assert finding["extra"]["unreachable_count"] == 2
        assert {r["id"] for r in finding["related"]} == {"2", "3"}

    def test_universal_accept_is_both_broad_and_catch_all(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(fw_forward=[_rule(1, action="accept"), _rule(2, action="drop", sources=["10.0.0.0/8"])])
        )
        kinds = _kinds(report)
        assert "overly_broad" in kinds
        assert "unreachable_after_any" in kinds


# --- hardware filtering ------------------------------------------------------


class TestHardwareHygiene:
    def test_inactive_list_rules_are_reported_once(self):
        # Active mode is src-ip; enabled dst-ip rules silently do nothing.
        report = rule_hygiene.analyze_snapshot(
            _snap(
                hw_settings=S.HwFilterSettings(mode="src-ip"),
                hw_rules_dst_ip=[
                    S.HwRuleDstIp(id="d1", destination_ip="203.0.113.1", comment="Old block"),
                    S.HwRuleDstIp(id="d2", destination_ip="203.0.113.2"),
                ],
            )
        )
        found = [f for f in report["findings"] if f["kind"] == "hw_inactive"]
        assert len(found) == 1
        assert found[0]["severity"] == "warning"
        assert found[0]["table"] == "hw_filter"
        assert found[0]["extra"] == {"inactive_count": 2, "list_mode": "dst-ip", "active_mode": "src-ip"}
        assert found[0]["rule"]["id"] == "d1"
        assert [r["id"] for r in found[0]["related"]] == ["d2"]

    def test_disabled_inactive_rules_are_not_reported(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                hw_settings=S.HwFilterSettings(mode="src-ip"),
                hw_rules_dst_ip=[S.HwRuleDstIp(id="d1", destination_ip="203.0.113.1", enabled=False)],
            )
        )
        assert [f for f in report["findings"] if f["table"] == "hw_filter"] == []

    def test_duplicate_in_active_list_is_redundant(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                hw_settings=S.HwFilterSettings(mode="src-ip"),
                hw_rules_src_ip=[
                    S.HwRuleSrcIp(id="s1", source_ip="192.0.2.10", comment="Bad host"),
                    S.HwRuleSrcIp(id="s2", source_ip="192.0.2.10", comment="Bad host again"),
                ],
            )
        )
        found = [f for f in report["findings"] if f["reason_key"] == "hygiene_hw_duplicate"]
        assert len(found) == 1
        assert found[0]["kind"] == "redundant"
        assert found[0]["severity"] == "info"
        assert found[0]["rule"]["id"] == "s2"
        assert found[0]["related"][0]["id"] == "s1"

    def test_active_list_without_duplicates_is_clean(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                hw_settings=S.HwFilterSettings(mode="src-and-dst-ip"),
                hw_rules_src_dst_ip=[
                    S.HwRuleSrcDstIp(id="p1", source_ip="192.0.2.10", destination_ip="203.0.113.1"),
                    # Same source, DIFFERENT destination — not a duplicate pair.
                    S.HwRuleSrcDstIp(id="p2", source_ip="192.0.2.10", destination_ip="203.0.113.2"),
                ],
            )
        )
        assert [f for f in report["findings"] if f["table"] == "hw_filter"] == []

    def test_unavailable_feature_produces_no_findings(self):
        # hw_settings=None (pre-v22 NGFW) — even configured-looking lists are
        # not judged; the feature simply is not there.
        report = rule_hygiene.analyze_snapshot(_snap(hw_rules_src_ip=[S.HwRuleSrcIp(id="s1", source_ip="192.0.2.10")]))
        assert [f for f in report["findings"] if f["table"] == "hw_filter"] == []


# --- chain isolation ---------------------------------------------------------


class TestChainIsolation:
    def test_forward_rule_does_not_shadow_input_rule(self):
        report = rule_hygiene.analyze_snapshot(
            _snap(
                fw_forward=[_rule(1, action="accept", sources=["10.0.0.0/8"])],
                fw_input=[_rule(2, action="drop", sources=["10.0.0.0/8"])],
            )
        )
        assert _by_rule(report, 2) == []

    def test_empty_snapshot_is_clean(self):
        report = rule_hygiene.analyze_snapshot(_snap())
        assert report["summary"]["total"] == 0
        assert report["findings"] == []


# --- endpoint ----------------------------------------------------------------


@pytest.fixture
def hygiene_app(monkeypatch):
    monkeypatch.setenv("STUCK_ENABLE_RULE_HYGIENE", "true")
    get_settings.cache_clear()
    application = create_app()
    application.state.settings.STUCK_COOKIE_SECURE = False
    try:
        yield application
    finally:
        get_settings.cache_clear()


@pytest.fixture
def disabled_hygiene_app(monkeypatch):
    monkeypatch.setenv("STUCK_ENABLE_RULE_HYGIENE", "false")
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


class TestHygieneEndpoint:
    def test_enabled_by_default(self, authenticated_client: TestClient):
        resp = authenticated_client.get("/api/rules/hygiene")
        assert resp.status_code == 200
        body = resp.json()
        assert set(body) >= {"binding", "rules_updated_at", "generated_at", "summary", "findings"}
        assert set(body["summary"]) >= {"total", "risk", "warning", "info", "possible"}
        assert isinstance(body["findings"], list)

    def test_binding_from_session(self, authenticated_client: TestClient):
        body = authenticated_client.get("/api/rules/hygiene").json()
        assert body["binding"]["server"] == NGFW_SERVER

    def test_requires_authentication(self, hygiene_app, ngfw_mock):
        with _client(hygiene_app) as c:
            assert c.get("/api/rules/hygiene").status_code == 401

    def test_disabled_returns_404(self, disabled_hygiene_app, ngfw_mock):
        with _client(disabled_hygiene_app) as c:
            _login(c)
            resp = c.get("/api/rules/hygiene")
            assert resp.status_code == 404
            assert resp.json()["error"]["code"] == "not_found"

    def test_session_reports_flag(self, authenticated_client: TestClient):
        assert authenticated_client.get("/api/session").json()["rule_hygiene_enabled"] is True

    def test_refresh_repulls_snapshot(self, authenticated_client: TestClient, ngfw_mock):
        # First call loads the (empty) snapshot lazily and caches it.
        assert authenticated_client.get("/api/rules/hygiene").json()["summary"]["total"] == 0

        # The NGFW config changes behind STUCK's back (a new any-any accept)…
        ngfw_mock.state["fw_forward"] = (200, [{"id": "fw.any", "enabled": True, "action": "accept"}])

        # …a plain call still serves the cached snapshot…
        assert authenticated_client.get("/api/rules/hygiene").json()["summary"]["total"] == 0

        # …and ?refresh=true re-pulls it and reports the new risk.
        body = authenticated_client.get("/api/rules/hygiene", params={"refresh": "true"}).json()
        assert body["summary"]["risk"] == 1
        assert body["findings"][0]["kind"] == "overly_broad"

    def test_binding_isolation_between_admins(self, hygiene_app, ngfw_mock):
        # Mirrors the export isolation invariant: each session analyses ITS OWN
        # binding's snapshot; another admin's load never leaks across.
        def _whoami(login):
            return {
                "login": login,
                "name": login,
                "role_id": "predefined_admin_readonly",
                "role_name": "Read-only administrator",
                "competence": ["admin_read"],
            }

        with _client(hygiene_app) as client_a, _client(hygiene_app) as client_b:
            ngfw_mock.state["whoami"] = (200, _whoami("adminA"))
            _login(client_a, login="adminA")
            assert client_a.get("/api/rules/hygiene").json()["summary"]["total"] == 0

            # NGFW gains an any-any rule; admin B loads a FRESH binding.
            ngfw_mock.state["fw_forward"] = (200, [{"id": "fw.any", "enabled": True, "action": "accept"}])
            ngfw_mock.state["whoami"] = (200, _whoami("adminB"))
            _login(client_b, login="adminB")

            body_b = client_b.get("/api/rules/hygiene").json()
            body_a = client_a.get("/api/rules/hygiene").json()

        assert body_b["binding"]["admin"] == "adminB"
        assert body_b["summary"]["risk"] == 1
        # A's cached binding is untouched by B's load.
        assert body_a["binding"]["admin"] == "adminA"
        assert body_a["summary"]["total"] == 0

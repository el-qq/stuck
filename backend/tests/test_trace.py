"""Tests for trace / users / rules-refresh + binding pool (contract v2.1 §3.4-3.6, §5.1)."""

from conftest import DEFAULT_USERS, NGFW_SERVER
from fastapi.testclient import TestClient

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
    "id": 3,  # NGFW returns numeric ids; backend must coerce to str
    "name": "Блокировка запрещённых",
    "access": "deny",
    "categories": ["cat.blocked"],
    "aliases": ["user.id.1"],
    "enabled": True,
}


def _whoami_profile(login: str) -> dict[str, object]:
    """Minimal valid canonical administrator profile for a mocked NGFW."""

    return {
        "login": login,
        "name": f"{login} display name",
        "role_id": "predefined_admin_readonly",
        "role_name": "Read-only administrator",
        "competence": ["admin_read"],
    }


class TestTraceAuth:
    def test_trace_requires_authentication(self, client: TestClient):
        resp = client.post("/api/trace", json={"url": "example.com"})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"


class TestHardwareFilterStage:
    """hw_filter — NIC-level drop, the FIRST stage of the pipeline."""

    def _trace(self, client, ngfw_mock, *, source_ip=None):
        body = {"url": "198.51.100.1", "user_id": "user.id.1"}
        if source_ip:
            body["source_ip"] = source_ip
        resp = client.post("/api/trace", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def test_stage_is_first_and_passes_without_rules(self, authenticated_client: TestClient, ngfw_mock):
        data = self._trace(authenticated_client, ngfw_mock)
        first = data["stages"][0]
        assert first["key"] == "hw_filter"
        assert first["status"] == "pass"
        assert first["detail"]["reason_key"] == "hw_no_matching_rule"

    def test_src_ip_mode_blocks_matching_source(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_rules_src_ip"] = (
            200,
            [{"id": "hw.1", "enabled": True, "source_ip": "192.0.2.10", "comment": "Bad host"}],
        )
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.10")
        first = data["stages"][0]
        assert first["status"] == "block"
        assert first["detail"]["rule_id"] == "hw.1"
        assert first["detail"]["reason_key"] == "hw_rule_blocked"
        assert data["summary"]["blocked_at"] == "hw_filter"
        # Everything after the hardware drop is not reached.
        assert {s["status"] for s in data["stages"][1:]} == {"na"}

    def test_src_ip_mode_passes_other_source(self, authenticated_client: TestClient, ngfw_mock):
        # user.id.1 gets a second active session so the OTHER source is valid
        # for the trace (invariant #8) while missing the hardware rule.
        ngfw_mock.state["auth_sessions"] = (
            200,
            [
                {"id": "s1", "user_object_id": "user.id.1", "subnet": "192.0.2.10/32"},
                {"id": "s3", "user_object_id": "user.id.1", "subnet": "192.0.2.20/32"},
            ],
        )
        ngfw_mock.state["hw_rules_src_ip"] = (
            200,
            [{"id": "hw.1", "enabled": True, "source_ip": "192.0.2.10", "comment": ""}],
        )
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.20")
        assert data["stages"][0]["status"] == "pass"

    def test_src_ip_mode_without_source_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        # Invariant #7: an enabled source rule may match; no source IP → unknown.
        ngfw_mock.state["hw_rules_src_ip"] = (
            200,
            [{"id": "hw.1", "enabled": True, "source_ip": "192.0.2.10", "comment": ""}],
        )
        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.1"})
        first = resp.json()["stages"][0]
        assert first["status"] == "unknown"
        assert first["detail"]["reason_key"] == "hw_source_ip_unknown"

    def test_dst_ip_mode_blocks_matching_destination(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_settings"] = (200, {"mode": "dst-ip"})
        ngfw_mock.state["hw_rules_dst_ip"] = (
            200,
            [{"id": "hw.2", "enabled": True, "destination_ip": "198.51.100.1", "comment": "Blocked dst"}],
        )
        data = self._trace(authenticated_client, ngfw_mock)
        assert data["stages"][0]["status"] == "block"
        assert data["stages"][0]["detail"]["rule_id"] == "hw.2"

    def test_src_and_dst_mode_requires_both_to_match(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_settings"] = (200, {"mode": "src-and-dst-ip"})
        ngfw_mock.state["hw_rules_src_dst_ip"] = (
            200,
            [
                {
                    "id": "hw.3",
                    "enabled": True,
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.1",
                    "comment": "",
                }
            ],
        )
        ngfw_mock.state["auth_sessions"] = (
            200,
            [
                {"id": "s1", "user_object_id": "user.id.1", "subnet": "192.0.2.10/32"},
                {"id": "s3", "user_object_id": "user.id.1", "subnet": "192.0.2.20/32"},
            ],
        )
        # Pair matches → block.
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.10")
        assert data["stages"][0]["status"] == "block"
        # Source differs → pass (destination alone is not enough).
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.20")
        assert data["stages"][0]["status"] == "pass"

    def test_only_active_mode_rules_apply(self, authenticated_client: TestClient, ngfw_mock):
        # A dst rule exists, but the active mode is src-ip → the dst list is inert.
        ngfw_mock.state["hw_rules_dst_ip"] = (
            200,
            [{"id": "hw.2", "enabled": True, "destination_ip": "198.51.100.1", "comment": ""}],
        )
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.10")
        assert data["stages"][0]["status"] == "pass"

    def test_disabled_rule_is_ignored(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_rules_src_ip"] = (
            200,
            [{"id": "hw.1", "enabled": False, "source_ip": "192.0.2.10", "comment": ""}],
        )
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.10")
        assert data["stages"][0]["status"] == "pass"

    def test_mac_mode_with_rules_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        # The trace has no MAC context — an enabled MAC rule may match anything.
        ngfw_mock.state["hw_settings"] = (200, {"mode": "mac"})
        ngfw_mock.state["hw_rules_mac"] = (
            200,
            [{"id": "hw.4", "enabled": True, "mac": "11:22:33:aa:bb:cc", "protocol": 2054, "comment": ""}],
        )
        data = self._trace(authenticated_client, ngfw_mock, source_ip="192.0.2.10")
        first = data["stages"][0]
        assert first["status"] == "unknown"
        assert first["detail"]["reason_key"] == "hw_mac_unknown"

    def test_unknown_mode_is_api_changed(self, authenticated_client: TestClient, ngfw_mock):
        # A future/unknown mode must NOT silently pass (fail-open): the closed
        # Literal turns it into api_changed at snapshot load.
        ngfw_mock.state["hw_settings"] = (200, {"mode": "quantum-filtering"})
        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.1"})
        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_rule_with_invalid_ip_is_api_changed(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_rules_src_ip"] = (
            200,
            [{"id": "hw.1", "enabled": True, "source_ip": "999.9.9.9", "comment": ""}],
        )
        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.1"})
        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_rule_missing_ip_field_is_api_changed(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_rules_src_ip"] = (200, [{"id": "hw.1", "enabled": True, "comment": ""}])
        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.1"})
        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_missing_endpoints_mean_not_supported(self, authenticated_client: TestClient, ngfw_mock):
        # Pre-v22 NGFW: the hw endpoints do not exist. The snapshot still loads
        # and the stage honestly reports "not supported" instead of failing.
        for key in ("hw_settings", "hw_rules_mac", "hw_rules_src_ip", "hw_rules_dst_ip", "hw_rules_src_dst_ip"):
            ngfw_mock.state[key] = (404, {"error": "not found"})
        data = self._trace(authenticated_client, ngfw_mock)
        first = data["stages"][0]
        assert first["key"] == "hw_filter"
        assert first["status"] == "skip"
        assert first["detail"]["reason_key"] == "hw_not_supported"
        # The rest of the pipeline still runs.
        assert data["stages"][1]["key"] == "pre_filter"
        assert data["stages"][1]["status"] != "na"

    def test_refresh_counts_include_hardware_rules(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["hw_rules_src_ip"] = (
            200,
            [{"id": "hw.1", "enabled": True, "source_ip": "192.0.2.10", "comment": ""}],
        )
        counts = authenticated_client.post("/api/rules/refresh").json()["counts"]
        assert counts["hardware_rules"] == 1


class TestExtendedFirewallPipeline:
    def test_preliminary_filter_blocks_first(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_pre_filter"] = (
            200,
            (
                '"Rule type";"Protocol";"Source IP-address";"Source port";'
                '"Destination IP-address";"Destination port";"TCP-flags";'
                '"TCP-flags to blocking";"Packet length, bytes";"Comment";"Enabled"\r\n'
                '"drop_rules";"None";"192.0.2.10";"None";"198.51.100.1";'
                '"443";"";"";"None";"Block test";"Enabled"\r\n'
            ),
        )

        response = authenticated_client.post(
            "/api/trace",
            json={
                "url": "198.51.100.1",
                "user_id": "user.id.1",
                "source_ip": "192.0.2.10",
            },
        )

        assert response.status_code == 200
        data = response.json()
        # hw_filter passes (no hardware rules); pre_filter is the second stage.
        assert data["stages"][1]["key"] == "pre_filter"
        assert data["stages"][1]["status"] == "block"
        assert data["summary"]["blocked_at"] == "pre_filter"

    def test_dnat_selects_input_for_translated_ngfw_address(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_dnat"] = (
            200,
            [
                {
                    "id": "dnat.1",
                    "action": "dnat",
                    "sources": [{"addresses": ["user.id.1"]}],
                    "destinations": [{"addresses": ["any"]}],
                    "source_ports": ["any"],
                    "destination_ports": ["any"],
                    "incoming_interface": "any",
                    "timetable": ["any"],
                    "change_destination_address": "192.0.2.254",
                    "change_destination_port": "8443",
                }
            ],
        )
        ngfw_mock.state["fw_input"] = (
            200,
            [{"id": "input.1", "action": "accept"}],
        )

        response = authenticated_client.post(
            "/api/trace",
            json={
                "url": "203.0.113.5",
                "user_id": "user.id.1",
                "source_ip": "192.0.2.10",
            },
        )

        assert response.status_code == 200
        data = response.json()
        stages = {stage["key"]: stage for stage in data["stages"]}
        assert stages["dnat"]["status"] == "applied"
        assert data["target"]["effective_destination_ip"] == "192.0.2.254"
        assert data["target"]["effective_destination_port"] == 8443
        assert stages["firewall"]["detail"]["firewall_table"] == "input"
        assert stages["firewall"]["status"] == "pass"
        assert stages["snat"]["status"] == "skip"
        assert stages["snat"]["detail"]["reason_key"] == "snat_not_applicable_input"

    def test_explicit_snat_is_reported(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (
            200,
            [{"id": "forward.1", "action": "accept"}],
        )
        ngfw_mock.state["fw_snat"] = (
            200,
            [
                {
                    "id": "snat.1",
                    "action": "snat",
                    "sources": [{"addresses": ["user.id.1"]}],
                    "destinations": [{"addresses": ["any"]}],
                    "source_ports": ["any"],
                    "destination_ports": ["any"],
                    "outgoing_interface": "any",
                    "timetable": ["any"],
                    "change_source_address": "198.51.100.99",
                }
            ],
        )

        response = authenticated_client.post(
            "/api/trace",
            json={
                "url": "203.0.113.5",
                "user_id": "user.id.1",
                "source_ip": "192.0.2.10",
            },
        )

        assert response.status_code == 200
        snat = next(stage for stage in response.json()["stages"] if stage["key"] == "snat")
        assert snat["status"] == "applied"
        assert snat["detail"]["translated_source_ip"] == "198.51.100.99"

    def test_dnat_with_unknown_destination_port_object_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_dnat"] = (
            200,
            [
                {
                    "id": "dnat.missing-port",
                    "action": "dnat",
                    "destinations": [{"addresses": ["any"]}],
                    "destination_ports": ["port.missing"],
                }
            ],
        )

        response = authenticated_client.post("/api/trace", json={"url": "203.0.113.5", "user_id": "user.id.1"})

        assert response.status_code == 200
        dnat = next(stage for stage in response.json()["stages"] if stage["key"] == "dnat")
        assert dnat["status"] == "unknown"
        assert dnat["detail"]["reason_key"] == "fw_port_unknown"

    def test_user_source_addresses_are_live_and_user_scoped(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["auth_sessions"] = (
            200,
            [
                {"id": "a", "user_object_id": "user.id.1", "subnet": "10.0.0.2/24"},
                {"id": "b", "user_object_id": "user.id.1", "subnet": "10.0.0.3/24"},
                {"id": "c", "user_object_id": "user.id.1", "subnet": "10.0.0.4/24", "state_flags": 1},
                {"id": "d", "user_object_id": "user.id.2", "subnet": "10.0.0.5/24"},
            ],
        )

        response = authenticated_client.get("/api/users/user.id.1/source-addresses")

        assert response.status_code == 200
        assert [item["ip"] for item in response.json()["addresses"]] == [
            "10.0.0.2",
            "10.0.0.3",
        ]
        assert all(item["active"] for item in response.json()["addresses"])
        assert not any(item["assigned"] for item in response.json()["addresses"])

    def test_assigned_ip_is_available_without_a_live_session(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["auth_sessions"] = (200, [])
        ngfw_mock.state["auth_rules"] = (
            200,
            [
                {
                    "id": "auth.rule.1",
                    "enabled": True,
                    "ip": "10.20.30.40",
                    "mac": None,
                    "user_object_id": "user.id.1",
                    "always_logged": True,
                },
                {
                    "id": "auth.rule.2",
                    "enabled": False,
                    "ip": "10.20.30.41",
                    "mac": None,
                    "user_object_id": "user.id.1",
                    "always_logged": True,
                },
            ],
        )

        addresses = authenticated_client.get("/api/users/user.id.1/source-addresses")
        trace = authenticated_client.post("/api/trace", json={"url": "example.com", "user_id": "user.id.1"})

        assert addresses.status_code == 200
        assert addresses.json()["addresses"] == [
            {
                "ip": "10.20.30.40",
                "subnet": "10.20.30.40",
                "external_ip": None,
                "auth_module": "ip_permanent",
                "node_name": None,
                "active": False,
                "assigned": True,
            }
        ]
        assert trace.status_code == 200
        assert trace.json()["target"]["source_ip"] == "10.20.30.40"

    def test_user_without_any_ip_can_still_be_traced(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["auth_sessions"] = (200, [])
        ngfw_mock.state["auth_rules"] = (200, [])
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "forward.user",
                    "action": "accept",
                    "sources": [{"addresses": ["user.id.1"]}],
                    "destinations": [{"addresses": ["any"]}],
                    "destination_ports": ["any"],
                    "timetable": ["any"],
                }
            ],
        )

        response = authenticated_client.post("/api/trace", json={"url": "example.com", "user_id": "user.id.1"})

        assert response.status_code == 200
        assert response.json()["target"]["source_ip"] is None
        assert response.json()["user"]["id"] == "user.id.1"
        firewall = next(stage for stage in response.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "pass"
        assert firewall["detail"]["rule_id"] == "forward.user"

    def test_missing_source_ip_does_not_skip_an_earlier_ip_rule(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["auth_sessions"] = (200, [])
        ngfw_mock.state["auth_rules"] = (200, [])
        ngfw_mock.state["aliases"] = (
            200,
            [
                {
                    "id": "ip_address.id.source",
                    "type": "ip_address",
                    "value": "10.20.30.40",
                }
            ],
        )
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "forward.ip-deny",
                    "action": "drop",
                    "sources": [{"addresses": ["ip_address.id.source"]}],
                    "destinations": [{"addresses": ["any"]}],
                    "destination_ports": ["any"],
                    "timetable": ["any"],
                },
                {
                    "id": "forward.user-allow",
                    "action": "accept",
                    "sources": [{"addresses": ["user.id.1"]}],
                    "destinations": [{"addresses": ["any"]}],
                    "destination_ports": ["any"],
                    "timetable": ["any"],
                },
            ],
        )

        response = authenticated_client.post("/api/trace", json={"url": "203.0.113.5", "user_id": "user.id.1"})

        assert response.status_code == 200
        firewall = next(stage for stage in response.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "forward.ip-deny"
        assert firewall["detail"]["reason_key"] == "source_ip_unknown"


class TestTraceValidation:
    def test_trace_empty_url(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/trace", json={"url": " "})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_trace_missing_url(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/trace", json={})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "validation_error"

    def test_trace_unknown_user_not_found(self, authenticated_client: TestClient):
        """Unknown user_id → 404 not_found (contract §3.5)."""
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "user_id": "no.such.user"})
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"


class TestTraceStages:
    def test_always_all_stages_in_fixed_order(self, authenticated_client: TestClient, ngfw_mock):
        """Contract §5.3: stages always contain every key in fixed order."""
        resp = authenticated_client.post("/api/trace", json={"url": "example.com"})

        assert resp.status_code == 200
        data = resp.json()
        stages = data["stages"]
        assert [s["key"] for s in stages] == STAGE_KEYS
        assert [s["order"] for s in stages] == list(range(1, len(STAGE_KEYS) + 1))
        assert ngfw_mock.routes["categorize"].call_count == 1
        for s in stages:
            assert s["title_key"] == f"stage.{s['key']}"
            assert s["status"] in (
                "pass",
                "block",
                "limited",
                "resolved",
                "active",
                "applied",
                "conditional",
                "skip",
                "bypass",
                "unknown",
                "na",
            )
        # v2: the trace reports which snapshot it was computed on.
        assert isinstance(data["rules_updated_at"], str)

    def test_all_stages_even_when_blocked(self, authenticated_client: TestClient, ngfw_mock):
        """Blocked traces still return the full pipeline."""
        ngfw_mock.state["cf_rules"] = (200, [CF_DENY_RULE])
        ngfw_mock.state["categorize"] = (
            200,
            {"all": ["cat.blocked"], "sky": [], "normalizedUrl": "rts.rs"},
        )

        resp = authenticated_client.post("/api/trace", json={"url": "rts.rs", "user_id": "user.id.1"})

        assert resp.status_code == 200
        stages = resp.json()["stages"]
        assert [s["key"] for s in stages] == STAGE_KEYS

    def test_no_forward_rule_defaults_to_allow_for_a_user(self, authenticated_client: TestClient):
        """Documented FORWARD default is ALLOW *for users*
        (docs/source/docs-ru-ngfw-firewall-tables.md): with a selected user and
        no matching rule the firewall passes."""
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "user_id": "user.id.1"})

        assert resp.status_code == 200
        data = resp.json()
        summary = data["summary"]
        # DNS policy has no dry-run → the honest end verdict stays conditional,
        # but the firewall itself now passes by the documented default policy.
        assert summary["verdict"] == "conditional"
        assert summary["blocked_at"] is None
        by_key = {s["key"]: s for s in data["stages"]}
        assert by_key["firewall"]["status"] == "pass"
        assert by_key["firewall"]["detail"]["reason_key"] == "fw_default_allow"
        assert by_key["destination"]["status"] == "conditional"
        assert not any(s["status"] == "block" for s in data["stages"])

    def test_forward_default_allow_requires_a_user_subject(self, authenticated_client: TestClient):
        """Without a selected user the direction is unprovable (WAN→LAN is
        blocked by a system tail rule) → conservative unknown, never a pass."""
        resp = authenticated_client.post("/api/trace", json={"url": "example.com"})

        assert resp.status_code == 200
        by_key = {s["key"]: s for s in resp.json()["stages"]}
        assert by_key["firewall"]["status"] == "unknown"
        assert by_key["firewall"]["detail"]["reason_key"] == "fw_default_policy_unknown"

    def test_lan_source_without_user_defaults_to_allow(self, authenticated_client: TestClient):
        """A source IP inside a LAN interface network proves the user side even
        without a selected user → the documented default ALLOW applies."""
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "source_ip": "192.0.2.77"})

        assert resp.status_code == 200
        by_key = {s["key"]: s for s in resp.json()["stages"]}
        assert by_key["firewall"]["status"] == "pass"
        assert by_key["firewall"]["detail"]["reason_key"] == "fw_default_allow"

    def test_single_connection_settings_object_is_accepted(self, authenticated_client: TestClient, ngfw_mock):
        """The documented single-object form remains safe to reduce to CIDRs."""
        ngfw_mock.state["connection_settings"] = (
            200,
            {"id": "if.lan", "enabled": True, "role": "lan", "l3": ["192.0.2.254/24"], "config": {"secret": "x"}},
        )

        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "source_ip": "192.0.2.77"})

        assert resp.status_code == 200
        firewall = next(stage for stage in resp.json()["stages"] if stage["key"] == "firewall")
        assert firewall["detail"]["reason_key"] == "fw_default_allow"

    def test_invalid_lan_enabled_value_fails_closed(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["connection_settings"] = (
            200,
            [{"id": "if.lan", "enabled": "false", "role": "lan", "l3": ["192.0.2.254/24"]}],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "source_ip": "192.0.2.77"})

        assert resp.status_code == 502
        assert resp.json()["error"]["code"] == "api_changed"

    def test_non_lan_source_without_user_stays_unknown(self, authenticated_client: TestClient):
        """A source outside every LAN network cannot prove the direction."""
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "source_ip": "198.51.100.77"})

        assert resp.status_code == 200
        by_key = {s["key"]: s for s in resp.json()["stages"]}
        assert by_key["firewall"]["status"] == "unknown"
        assert by_key["firewall"]["detail"]["reason_key"] == "fw_default_policy_unknown"

    def test_dns_forward_zone_is_recognized(self, authenticated_client: TestClient, ngfw_mock):
        """A host under a local forward zone: the NGFW resolves it itself; the
        machine-local resolver cannot see that answer → honest unknown."""
        ngfw_mock.state["dns_zones_forward"] = (
            200,
            [{"id": "zone.1", "name": "stuck-dns.test", "enabled": True, "servers": ["192.0.2.53"], "comment": ""}],
        )
        resp = authenticated_client.post("/api/trace", json={"url": "host.stuck-dns.test", "user_id": "user.id.1"})

        assert resp.status_code == 200
        dns = next(s for s in resp.json()["stages"] if s["key"] == "dns")
        assert dns["status"] == "unknown"
        assert dns["detail"]["reason_key"] == "dns_zone_unresolved"
        assert dns["detail"]["rule_id"] == "zone.1"
        assert dns["detail"]["rule_name"] == "stuck-dns.test"

    def test_dns_zone_disabled_is_ignored(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["dns_zones_master"] = (
            200,
            [{"id": "zone.2", "name": "stuck-dns.test", "enabled": False, "config": "x", "comment": ""}],
        )
        resp = authenticated_client.post("/api/trace", json={"url": "host.stuck-dns.test", "user_id": "user.id.1"})

        dns = next(s for s in resp.json()["stages"] if s["key"] == "dns")
        assert dns["detail"]["reason_key"] != "dns_zone_unresolved"

    def test_dns_master_zone_does_not_reuse_or_query_the_system_resolver(
        self, authenticated_client: TestClient, ngfw_mock, monkeypatch
    ):
        """A resolvable name can have a different NGFW master-zone answer, so
        neither the local result nor downstream IP-rule evaluation may use it."""
        ngfw_mock.state["dns_zones_master"] = (
            200,
            [{"id": "zone.3", "name": "localhost", "enabled": True, "config": "x", "comment": ""}],
        )
        ngfw_mock.state["aliases"] = (
            200,
            [
                {"id": "country.rs", "type": "country", "value": "RS"},
                {"id": "ip.loopback", "type": "ip", "value": "127.0.0.1"},
            ],
        )
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fw.country",
                    "enabled": True,
                    "action": "drop",
                    "destinations": [{"addresses": ["country.rs"]}],
                },
                {
                    "id": "fw.loopback",
                    "enabled": True,
                    "action": "drop",
                    "destinations": [{"addresses": ["ip.loopback"]}],
                },
            ],
        )

        async def system_dns_must_not_run(_: str) -> str:
            raise AssertionError("local NGFW zone must not query STUCK system DNS")

        monkeypatch.setattr("app.domain.trace_engine.resolve_ip", system_dns_must_not_run)

        # "localhost" would resolve locally, but that is not evidence of the
        # answer from the NGFW master zone and must not even be looked up.
        resp = authenticated_client.post("/api/trace", json={"url": "localhost", "user_id": "user.id.1"})

        data = resp.json()
        dns = next(s for s in data["stages"] if s["key"] == "dns")
        firewall = next(s for s in data["stages"] if s["key"] == "firewall")
        assert data["target"]["resolved_ip"] is None
        assert dns["status"] == "unknown"
        assert dns["detail"]["reason_key"] == "dns_zone_unresolved"
        assert dns["detail"]["rule_id"] == "zone.3"
        assert "resolved_ip" not in dns["detail"]
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.country"
        assert firewall["detail"]["reason_key"] == "fw_destination_unknown"

    def test_unknown_destination_object_stops_at_the_earlier_rule(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fw.missing-object",
                    "enabled": True,
                    "action": "drop",
                    "destinations": [{"addresses": ["ip.missing"]}],
                }
            ],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.10", "user_id": "user.id.1"})

        assert resp.status_code == 200
        firewall = next(stage for stage in resp.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.missing-object"
        assert firewall["detail"]["reason_key"] == "fw_object_unknown"

    def test_country_ip_list_without_geoip_data_stops_at_the_earlier_rule(
        self, authenticated_client: TestClient, ngfw_mock
    ):
        # The documented list_of_iplists object contains GeoIP list IDs, not
        # CIDRs. STUCK has no matching read-only GeoIP dataset.
        ngfw_mock.state["aliases"] = (
            200,
            [{"id": "list_of_iplists.id.ru", "type": "list_of_iplists", "values": ["iplist.ru"]}],
        )
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fw.country-list",
                    "enabled": True,
                    "action": "drop",
                    "destinations": [{"addresses": ["list_of_iplists.id.ru"]}],
                }
            ],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.10", "user_id": "user.id.1"})

        assert resp.status_code == 200
        firewall = next(stage for stage in resp.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.country-list"
        assert firewall["detail"]["reason_key"] == "fw_object_unknown"

    def test_unknown_source_object_stops_at_the_earlier_rule(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fw.missing-source-object",
                    "enabled": True,
                    "action": "drop",
                    "sources": [{"addresses": ["ip.missing"]}],
                }
            ],
        )

        resp = authenticated_client.post(
            "/api/trace",
            json={"url": "198.51.100.10", "user_id": "user.id.1", "source_ip": "192.0.2.10"},
        )

        assert resp.status_code == 200
        firewall = next(stage for stage in resp.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.missing-source-object"
        assert firewall["detail"]["reason_key"] == "fw_object_unknown"

    def test_unknown_destination_port_object_stops_at_the_earlier_rule(
        self, authenticated_client: TestClient, ngfw_mock
    ):
        ngfw_mock.state["fw_forward"] = (
            200,
            [{"id": "fw.missing-port", "enabled": True, "action": "drop", "destination_ports": ["port.missing"]}],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.10", "user_id": "user.id.1"})

        assert resp.status_code == 200
        firewall = next(stage for stage in resp.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.missing-port"
        assert firewall["detail"]["reason_key"] == "fw_port_unknown"

    def test_unknown_firewall_action_is_not_reported_as_a_block(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (200, [{"id": "fw.future-action", "enabled": True, "action": "future_action"}])

        resp = authenticated_client.post("/api/trace", json={"url": "198.51.100.10", "user_id": "user.id.1"})

        assert resp.status_code == 200
        firewall = next(stage for stage in resp.json()["stages"] if stage["key"] == "firewall")
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["reason_key"] == "fw_action_unknown"
        assert resp.json()["summary"]["blocked_at"] is None

    def test_refresh_counts_include_lan_and_dns(self, authenticated_client: TestClient, ngfw_mock):
        counts = authenticated_client.post("/api/rules/refresh").json()["counts"]
        assert counts["lan_networks"] == 1
        assert counts["dns_zones"] == 0

    def test_non_matching_drop_rule_still_defaults_to_allow(self, authenticated_client: TestClient, ngfw_mock):
        """The default applies when rules EXIST but none matches — not only for
        an empty table."""
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fwd.1",
                    "action": "drop",
                    "sources": [{"addresses": ["user.id.1"]}],
                    "destinations": [{"addresses": ["203.0.113.99"]}],
                    "enabled": True,
                }
            ],
        )
        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "user_id": "user.id.1"})

        assert resp.status_code == 200
        by_key = {s["key"]: s for s in resp.json()["stages"]}
        assert by_key["firewall"]["status"] == "pass"
        assert by_key["firewall"]["detail"]["reason_key"] == "fw_default_allow"

    def test_empty_input_table_stays_unknown(self, authenticated_client: TestClient, ngfw_mock):
        """INPUT (traffic to the NGFW itself) never borrows the FORWARD default:
        system rules guarding NGFW services are invisible to the read-only API."""
        resp = authenticated_client.post("/api/trace", json={"url": "192.0.2.254", "user_id": "user.id.1"})

        assert resp.status_code == 200
        by_key = {s["key"]: s for s in resp.json()["stages"]}
        assert by_key["firewall"]["detail"]["firewall_table"] == "input"
        assert by_key["firewall"]["status"] == "unknown"
        assert by_key["firewall"]["detail"]["reason_key"] == "fw_default_policy_unknown"

    def test_blocked_by_content_filter_as_user(self, authenticated_client: TestClient, ngfw_mock):
        """CF rule denies the URL category for the chosen user → block at content_filter."""
        ngfw_mock.state["cf_rules"] = (200, [CF_DENY_RULE])
        ngfw_mock.state["categorize"] = (
            200,
            {"all": ["cat.blocked"], "sky": [], "normalizedUrl": "rts.rs"},
        )

        resp = authenticated_client.post("/api/trace", json={"url": "rts.rs", "user_id": "user.id.1"})

        assert resp.status_code == 200
        data = resp.json()

        assert data["user"] == {"id": "user.id.1", "name": "John Doe", "login": "john"}

        cf = next(s for s in data["stages"] if s["key"] == "content_filter")
        assert cf["status"] == "block"
        assert cf["detail"]["rule_id"] == "3"
        assert cf["detail"]["action"] == "deny"
        assert cf["detail"]["reason_key"] == "cf_category_blocked"

        # Stages after the block are 'na' (contract §3.5 example).
        for key in ("antivirus", "firewall", "app_control", "ips", "destination"):
            stage = next(s for s in data["stages"] if s["key"] == key)
            assert stage["status"] == "na"

        assert data["summary"]["blocked_at"] == "content_filter"
        assert data["summary"]["verdict"] == "blocked"
        assert data["summary"]["reached_destination"] is False

    def test_cf_rule_for_other_user_does_not_block(self, authenticated_client: TestClient, ngfw_mock):
        """The same deny rule scoped to user.id.1 must NOT block a trace without a user."""
        ngfw_mock.state["cf_rules"] = (200, [CF_DENY_RULE])
        ngfw_mock.state["categorize"] = (
            200,
            {"all": ["cat.blocked"], "sky": [], "normalizedUrl": "rts.rs"},
        )

        resp = authenticated_client.post("/api/trace", json={"url": "rts.rs"})

        assert resp.status_code == 200
        # No user selected → the FORWARD default is not applied → unknown.
        assert resp.json()["summary"]["verdict"] == "unknown"

    def test_ips_bypass_for_user(self, authenticated_client: TestClient, ngfw_mock):
        """User in the IPS bypass list → ips stage status=bypass."""
        ngfw_mock.state["ips_bypass"] = (
            200,
            [{"id": "bypass.1", "aliases": ["user.id.1"], "enabled": True}],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "example.com", "user_id": "user.id.1"})

        assert resp.status_code == 200
        data = resp.json()
        ips = next(s for s in data["stages"] if s["key"] == "ips")
        assert ips["status"] == "bypass"
        assert ips["detail"]["rule_id"] == "bypass.1"
        assert ips["detail"]["reason_key"] == "ips_bypass"
        # Bypass is not a block; the empty FORWARD table falls back to the
        # documented default ALLOW for the selected user, and the DNS stage
        # keeps the end verdict conditional.
        assert data["summary"]["verdict"] == "conditional"

    def test_content_filter_disabled_is_skip(self, authenticated_client: TestClient, ngfw_mock):
        """CF module off → content_filter stage status=skip."""
        ngfw_mock.state["cf_state"] = (200, {"enabled": False})

        resp = authenticated_client.post("/api/trace", json={"url": "example.com"})

        assert resp.status_code == 200
        cf = next(s for s in resp.json()["stages"] if s["key"] == "content_filter")
        assert cf["status"] == "skip"
        assert cf["detail"]["module_enabled"] is False

    def test_antivirus_module_and_default_profile_are_active(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/trace", json={"url": "192.0.2.1"})

        assert resp.status_code == 200
        antivirus = next(stage for stage in resp.json()["stages"] if stage["key"] == "antivirus")
        assert antivirus["status"] == "active"
        assert antivirus["detail"]["module_enabled"] is True
        assert antivirus["detail"]["reason_key"] == "av_active_content_unknown"

    def test_active_antivirus_makes_reachability_conditional(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (
            200,
            [{"id": "fw.accept", "enabled": True, "action": "accept"}],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "192.0.2.1"})

        assert resp.status_code == 200
        data = resp.json()
        stages = {stage["key"]: stage for stage in data["stages"]}
        assert stages["antivirus"]["status"] == "active"
        assert stages["destination"]["status"] == "conditional"
        assert data["summary"]["verdict"] == "conditional"
        assert data["summary"]["reached_destination"] is False

    def test_current_ngfw_any_sentinels_do_not_hide_content_filter_failure(
        self, authenticated_client: TestClient, ngfw_mock
    ):
        ngfw_mock.state["cf_rules"] = (
            200,
            [
                {
                    **{key: value for key, value in CF_DENY_RULE.items() if key != "aliases"},
                    "src_aliases": [{"aliases": ["user.id.1"], "negate": False}],
                    "timetable": ["any"],
                }
            ],
        )
        ngfw_mock.state["categorize"] = (
            200,
            {"all": ["cat.blocked"], "sky": [], "normalizedUrl": "blocked.example"},
        )

        resp = authenticated_client.post(
            "/api/trace",
            json={"url": "blocked.example", "user_id": "user.id.1"},
        )

        assert resp.status_code == 200
        assert resp.json()["summary"]["blocked_at"] == "content_filter"

    def test_current_ngfw_any_sentinels_do_not_hide_firewall_failure(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fw.1",
                    "enabled": True,
                    "protocol": "any",
                    "sources": [{"addresses": ["user.id.1"], "addresses_negate": False}],
                    "source_ports": ["any"],
                    "incoming_interface": "any",
                    "destinations": [{"addresses": ["any"], "addresses_negate": False}],
                    "destination_ports": ["any"],
                    "outgoing_interface": "any",
                    "hip_profiles": [],
                    "timetable": ["any"],
                    "action": "drop",
                }
            ],
        )

        resp = authenticated_client.post(
            "/api/trace",
            json={"url": "blocked.example", "user_id": "user.id.1"},
        )

        assert resp.status_code == 200
        assert resp.json()["summary"]["blocked_at"] == "firewall"

    def test_content_filter_uses_first_matching_rule(self, authenticated_client: TestClient, ngfw_mock):
        common = {
            "enabled": True,
            "src_aliases": [{"aliases": ["user.id.1"], "negate": False}],
            "categories": ["cat.ordered"],
            "timetable": ["any"],
        }
        ngfw_mock.state["cf_rules"] = (
            200,
            [
                {**common, "id": "cf.first", "name": "first allow", "access": "allow"},
                {**common, "id": "cf.second", "name": "later deny", "access": "deny"},
            ],
        )
        ngfw_mock.state["categorize"] = (
            200,
            {"all": ["cat.ordered"], "sky": [], "normalizedUrl": "ordered.example"},
        )
        ngfw_mock.state["av_state"] = (200, {"enabled": False})
        ngfw_mock.state["fw_forward"] = (
            200,
            [
                {
                    "id": "fw.allow",
                    "enabled": True,
                    "protocol": "any",
                    "sources": [{"addresses": ["any"], "addresses_negate": False}],
                    "source_ports": ["any"],
                    "incoming_interface": "any",
                    "destinations": [{"addresses": ["any"], "addresses_negate": False}],
                    "destination_ports": ["any"],
                    "outgoing_interface": "any",
                    "timetable": ["any"],
                    "action": "accept",
                }
            ],
        )

        resp = authenticated_client.post(
            "/api/trace",
            json={"url": "ordered.example", "user_id": "user.id.1"},
        )

        assert resp.status_code == 200
        data = resp.json()
        cf = next(stage for stage in data["stages"] if stage["key"] == "content_filter")
        assert cf["status"] == "pass"
        assert cf["detail"]["rule_id"] == "cf.first"
        # The first CF allow still wins. DNS policy for a domain cannot be
        # confirmed through the NGFW read-only API, so the overall verdict is
        # intentionally unknown rather than a false end-to-end allow.
        assert data["summary"]["verdict"] == "unknown"

    def test_speed_limit_rule_matches_destination_ip(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["aliases"] = (
            200,
            [{"id": "ip.id.2", "type": "ip", "value": "66.66.4.4"}],
        )
        ngfw_mock.state["shaper_rules"] = (
            200,
            [
                {
                    "id": "1",
                    "name": "Limit 66.66.4.4",
                    "aliases": ["ip.id.2"],
                    "apply_to": "group",
                    "speed_value": 1000,
                    "enabled": True,
                }
            ],
        )

        resp = authenticated_client.post("/api/trace", json={"url": "66.66.4.4"})

        assert resp.status_code == 200
        stages = {stage["key"]: stage for stage in resp.json()["stages"]}
        assert stages["rate_limit"]["status"] == "limited"
        assert stages["rate_limit"]["detail"]["rule_id"] == "1"
        assert stages["rate_limit"]["detail"]["speed_kbps"] == 1000
        assert stages["rate_limit"]["detail"]["limit_scope"] == "group"
        assert stages["dns"]["status"] == "skip"
        assert stages["dns"]["detail"]["reason_key"] == "dns_not_required"

    def test_firewall_ip_port_uses_order_across_many_rules(self, authenticated_client: TestClient, ngfw_mock):
        def rule(
            rule_id: str,
            destination: str,
            destination_port: str,
            action: str,
        ) -> dict:
            return {
                "id": rule_id,
                "enabled": True,
                "protocol": "protocol.tcp",
                "sources": [{"addresses": ["user.id.1"], "addresses_negate": False}],
                "source_ports": ["any"],
                "incoming_interface": "any",
                "destinations": [{"addresses": [destination], "addresses_negate": False}],
                "destination_ports": [destination_port],
                "outgoing_interface": "any",
                "hip_profiles": [],
                "timetable": ["any"],
                "action": action,
            }

        noise = [rule(f"fw.noise.{index}", "ip.id.noise", "any", "drop") for index in range(30)]
        ngfw_mock.state["aliases"] = (
            200,
            [
                {"id": "ip.id.noise", "type": "ip", "value": "192.0.2.200"},
                {"id": "ip.id.port-test", "type": "ip", "value": "198.51.100.25"},
                {"id": "port.id.9443", "type": "port", "value": 9443},
            ],
        )
        ngfw_mock.state["fw_forward"] = (
            200,
            noise
            + [
                rule("fw.first-drop", "ip.id.port-test", "port.id.9443", "drop"),
                rule("fw.later-accept", "ip.id.port-test", "port.id.9443", "accept"),
                rule("fw.broad-accept", "ip.id.port-test", "any", "accept"),
            ],
        )
        ngfw_mock.state["av_state"] = (200, {"enabled": False})

        blocked = authenticated_client.post(
            "/api/trace",
            json={"url": "198.51.100.25:9443", "user_id": "user.id.1"},
        )
        allowed = authenticated_client.post(
            "/api/trace",
            json={"url": "198.51.100.25:443", "user_id": "user.id.1"},
        )

        assert blocked.status_code == 200
        blocked_data = blocked.json()
        blocked_fw = next(stage for stage in blocked_data["stages"] if stage["key"] == "firewall")
        assert blocked_data["target"]["dst_port"] == 9443
        assert blocked_data["summary"]["verdict"] == "blocked"
        assert blocked_fw["detail"]["rule_id"] == "fw.first-drop"

        assert allowed.status_code == 200
        allowed_data = allowed.json()
        allowed_fw = next(stage for stage in allowed_data["stages"] if stage["key"] == "firewall")
        assert allowed_data["target"]["dst_port"] == 443
        assert allowed_data["summary"]["verdict"] == "allowed"
        assert allowed_fw["detail"]["rule_id"] == "fw.broad-accept"


class TestUsers:
    def test_users_requires_authentication(self, client: TestClient):
        resp = client.get("/api/users")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"

    def test_users_returns_list(self, authenticated_client: TestClient):
        resp = authenticated_client.get("/api/users")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["users"]) == len(DEFAULT_USERS)
        first = data["users"][0]
        assert first["id"] == "user.id.1"
        assert first["name"] == "John Doe"
        assert first["login"] == "john"
        assert first["enabled"] is True
        assert first["group_id"] is None
        second = data["users"][1]
        assert second["enabled"] is False
        assert second["domain_type"] == "ad"
        assert second["group_id"] == "group.id.1"
        # v2: renamed from loaded_at.
        assert "rules_updated_at" in data
        assert "loaded_at" not in data
        assert isinstance(data["rules_updated_at"], str)

    def test_users_search_filter(self, authenticated_client: TestClient):
        resp = authenticated_client.get("/api/users", params={"search": "jane"})

        assert resp.status_code == 200
        users = resp.json()["users"]
        assert len(users) == 1
        assert users[0]["login"] == "jane"

    def test_users_cached_flag(self, authenticated_client: TestClient):
        """First call loads from NGFW (cached=false), second serves the pool."""
        resp1 = authenticated_client.get("/api/users")
        assert resp1.status_code == 200
        assert resp1.json()["cached"] is False

        resp2 = authenticated_client.get("/api/users")
        assert resp2.status_code == 200
        assert resp2.json()["cached"] is True


class TestBindingPool:
    """v2.1 invariant 9 + §5.1: pool survives logout, refresh reloads, bindings isolated."""

    def test_snapshot_is_pooled_not_refetched(self, authenticated_client: TestClient, ngfw_mock):
        """After the first load, NGFW data changes are NOT visible until refresh."""
        resp1 = authenticated_client.get("/api/users")
        assert len(resp1.json()["users"]) == 2

        ngfw_mock.state["users"] = (
            200,
            DEFAULT_USERS + [{"id": "user.id.3", "name": "New", "login": "new"}],
        )
        resp2 = authenticated_client.get("/api/users")
        assert len(resp2.json()["users"]) == 2
        assert resp2.json()["cached"] is True

    def test_rules_refresh_reloads_snapshot(self, authenticated_client: TestClient, ngfw_mock):
        """POST /api/rules/refresh forces a reload from NGFW."""
        assert len(authenticated_client.get("/api/users").json()["users"]) == 2

        ngfw_mock.state["users"] = (
            200,
            DEFAULT_USERS + [{"id": "user.id.3", "name": "New", "login": "new"}],
        )

        refresh = authenticated_client.post("/api/rules/refresh")
        assert refresh.status_code == 200
        body = refresh.json()
        assert body["ok"] is True
        # v2: renamed from loaded_at.
        assert "rules_updated_at" in body
        assert "loaded_at" not in body
        assert body["counts"]["users"] == 3

        resp = authenticated_client.get("/api/users")
        assert len(resp.json()["users"]) == 3

    def test_rules_refresh_counts_keys(self, authenticated_client: TestClient):
        resp = authenticated_client.post("/api/rules/refresh")

        assert resp.status_code == 200
        counts = resp.json()["counts"]
        for key in (
            "users",
            "firewall_forward",
            "firewall_input",
            "content_filter_rules",
            "speed_limit_rules",
            "ips_bypass",
            "aliases",
        ):
            assert key in counts, f"missing counts.{key}"

    def test_rules_refresh_requires_authentication(self, client: TestClient):
        resp = client.post("/api/rules/refresh")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "not_authenticated"

    def test_reference_scenario_5_1(self, client: TestClient, ngfw_mock, valid_login_data, binding_pool):
        """Contract §5.1: login → rules(T1) → logout → login → cache(T1) → refresh(T2>T1)."""
        # 1. First login: no snapshot for the binding yet.
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200
        assert resp.json()["session"]["first_login"] is True
        assert resp.json()["session"]["rules_updated_at"] is None

        # 2. Rules load (T1).
        assert client.get("/api/users").status_code == 200
        binding = binding_pool.get(valid_login_data["login"], NGFW_SERVER)
        t1 = binding.rules_updated_at
        assert t1 is not None
        t1_iso = client.get("/api/session").json()["rules_updated_at"]
        assert t1_iso is not None

        # 3. Logout: STUCK session + NGFW cookie die, pool survives.
        assert client.post("/api/auth/logout").status_code == 200
        assert ngfw_mock.routes["logout"].called
        assert binding_pool.has_snapshot(valid_login_data["login"], NGFW_SERVER)

        # 4. Re-login same binding: password re-checked, rules from cache.
        login_calls_before = ngfw_mock.routes["login"].call_count
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200
        assert ngfw_mock.routes["login"].call_count == login_calls_before + 1
        session = resp.json()["session"]
        assert session["first_login"] is False
        # 5. UI shows "rules updated: T1".
        assert session["rules_updated_at"] == t1_iso

        # Users still served from the pooled snapshot.
        users_calls = ngfw_mock.routes["users"].call_count
        resp = client.get("/api/users")
        assert resp.json()["cached"] is True
        assert ngfw_mock.routes["users"].call_count == users_calls

        # 6. Refresh: snapshot reloaded, T2 > T1.
        refresh = client.post("/api/rules/refresh")
        assert refresh.status_code == 200
        t2 = binding_pool.get(valid_login_data["login"], NGFW_SERVER).rules_updated_at
        assert t2 > t1

    def test_binding_isolation_other_admin(self, client: TestClient, ngfw_mock, valid_login_data, binding_pool):
        """Different admin on the same server = separate binding with its own snapshot."""
        # admin1 loads a 2-user snapshot.
        ngfw_mock.state["whoami"] = (200, _whoami_profile("admin"))
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200
        assert len(client.get("/api/users").json()["users"]) == 2

        # NGFW now returns 3 users; admin2 logs in and loads ITS OWN snapshot.
        ngfw_mock.state["users"] = (
            200,
            DEFAULT_USERS + [{"id": "user.id.3", "name": "New", "login": "new"}],
        )
        admin2 = {**valid_login_data, "login": "admin2"}
        ngfw_mock.state["whoami"] = (200, _whoami_profile("admin2"))
        resp = client.post("/api/auth/login", json=admin2)
        assert resp.status_code == 200
        assert resp.json()["session"]["first_login"] is True  # own binding, empty
        resp = client.get("/api/users")
        assert resp.json()["cached"] is False
        assert len(resp.json()["users"]) == 3

        # admin1's binding is untouched: re-login -> first_login=False, 2 users from cache.
        ngfw_mock.state["whoami"] = (200, _whoami_profile("admin"))
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.json()["session"]["first_login"] is False
        resp = client.get("/api/users")
        assert resp.json()["cached"] is True
        assert len(resp.json()["users"]) == 2

        # Two separate bindings exist in the pool.
        assert binding_pool.get("admin", NGFW_SERVER) is not None
        assert binding_pool.get("admin2", NGFW_SERVER) is not None

    def test_binding_isolation_other_server(self, client: TestClient, ngfw_mock, valid_login_data, binding_pool):
        """Same admin on a different server = separate binding (first_login=true)."""
        ngfw_mock.state["whoami"] = (200, _whoami_profile("admin"))
        assert client.post("/api/auth/login", json=valid_login_data).status_code == 200
        assert client.get("/api/users").status_code == 200  # snapshot for server 1

        # Mock the NGFW login on a second server host.
        import httpx as _httpx

        ngfw_mock.router.post("https://10.0.0.2:8443/web/auth/login").mock(
            return_value=_httpx.Response(
                200,
                json={"success": True},
                headers=[("set-cookie", "insecure-ideco-session=tok2; Path=/")],
            )
        )
        ngfw_mock.router.get("https://10.0.0.2:8443/web/whoami").mock(
            return_value=_httpx.Response(200, json=_whoami_profile("admin"))
        )

        resp = client.post("/api/auth/login", json={**valid_login_data, "server": "10.0.0.2"})
        assert resp.status_code == 200
        assert resp.json()["session"]["first_login"] is True
        assert resp.json()["session"]["rules_updated_at"] is None

    def test_pool_contains_no_secrets(self, authenticated_client: TestClient, binding_pool, valid_login_data):
        """v2.1 invariant: the pool holds ONLY the snapshot + timestamp — no cookies."""
        # Load the snapshot so the binding is fully populated.
        assert authenticated_client.get("/api/users").status_code == 200

        from conftest import NGFW_SESSION_VALUE

        binding = binding_pool.get(valid_login_data["login"], NGFW_SERVER)
        assert binding is not None

        # No cookie/secret-like attribute on the binding. ``saved_snapshots``
        # holds named rule snapshots (docs/source/snapshots.md) — non-secret
        # copies of the same snapshot data, checked below with the deep scan.
        attrs = vars(binding)
        assert set(attrs.keys()) == {"admin_login", "server", "snapshot", "saved_snapshots"}
        for name in attrs:
            assert "cookie" not in name.lower()
            assert "password" not in name.lower()
            assert "token" not in name.lower()

        # Deep check: neither the NGFW cookie value nor the password appear
        # anywhere in the pooled state.
        blob = repr(vars(binding)) + repr(vars(binding.snapshot))
        assert NGFW_SESSION_VALUE not in blob
        assert valid_login_data["password"] not in blob

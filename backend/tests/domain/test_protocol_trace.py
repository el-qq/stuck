"""Integration traces covering firewall/NAT/pre-filter protocol matching.

NGFW firewall rules restrict traffic by protocol (any/AH/ESP/GRE/ICMP/TCP/UDP/
TCP-or-UDP). A trace for a concrete protocol follows only the rules that can
apply; a trace for "Любой" (any) must not claim a verdict from a protocol-
specific rule and instead reports ``unknown`` (AGENTS.md invariant 7).
"""

import pytest
from fastapi.testclient import TestClient

# Public (non-NGFW) destination -> the firewall evaluates the FORWARD chain.
_PUBLIC_URL = "203.0.113.5"
_USER = "user.id.1"


def _forward_rule(rule_id, protocol, action, **extra):
    rule = {
        "id": rule_id,
        "action": action,
        "protocol": protocol,
        "sources": [{"addresses": [_USER]}],
        "destinations": [{"addresses": ["any"]}],
        "destination_ports": ["any"],
        "timetable": ["any"],
    }
    rule.update(extra)
    return rule


def _firewall_stage(response):
    assert response.status_code == 200, response.text
    return next(stage for stage in response.json()["stages"] if stage["key"] == "firewall")


def _trace(client, protocol, **body):
    payload = {"url": _PUBLIC_URL, "user_id": _USER, "protocol": protocol}
    payload.update(body)
    return client.post("/api/trace", json=payload)


class TestFirewallProtocolMatching:
    @pytest.mark.parametrize("protocol", ["ah", "esp", "gre", "icmp", "tcp", "udp"])
    def test_rule_of_the_traced_protocol_blocks(self, authenticated_client: TestClient, ngfw_mock, protocol):
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.block", f"protocol.{protocol}", "drop")])
        firewall = _firewall_stage(_trace(authenticated_client, protocol))
        assert firewall["status"] == "block"
        assert firewall["detail"]["rule_id"] == "fw.block"
        assert firewall["detail"]["reason_key"] == "fw_rule_blocked"

    @pytest.mark.parametrize("protocol", ["ah", "esp", "gre", "icmp", "tcp", "udp"])
    def test_rule_of_the_traced_protocol_accepts(self, authenticated_client: TestClient, ngfw_mock, protocol):
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.allow", f"protocol.{protocol}", "accept")])
        firewall = _firewall_stage(_trace(authenticated_client, protocol))
        assert firewall["status"] == "pass"
        assert firewall["detail"]["rule_id"] == "fw.allow"

    @pytest.mark.parametrize(
        ("rule_protocol", "traced"),
        [("protocol.udp", "tcp"), ("protocol.tcp", "udp"), ("protocol.icmp", "tcp"), ("protocol.gre", "esp")],
    )
    def test_rule_of_other_protocol_is_skipped(
        self, authenticated_client: TestClient, ngfw_mock, rule_protocol, traced
    ):
        # The drop rule cannot apply to the traced protocol, so the documented
        # default-allow for a selected user is reached instead of a block.
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.other", rule_protocol, "drop")])
        firewall = _firewall_stage(_trace(authenticated_client, traced))
        assert firewall["status"] == "pass"
        assert firewall["detail"]["reason_key"] == "fw_default_allow"

    def test_tcp_udp_rule_covers_a_tcp_trace(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.tcpudp", "protocol.tcp_udp", "drop")])
        firewall = _firewall_stage(_trace(authenticated_client, "tcp"))
        assert firewall["status"] == "block"
        assert firewall["detail"]["rule_id"] == "fw.tcpudp"

    def test_tcp_udp_trace_against_tcp_only_rule_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        # The request may be UDP, so a TCP-only rule cannot be resolved honestly.
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.tcp", "protocol.tcp", "drop")])
        firewall = _firewall_stage(_trace(authenticated_client, "tcp_udp"))
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.tcp"
        assert firewall["detail"]["reason_key"] == "fw_protocol_unknown"

    def test_any_trace_against_protocol_specific_rule_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.tcp", "protocol.tcp", "drop")])
        firewall = _firewall_stage(_trace(authenticated_client, "any"))
        assert firewall["status"] == "unknown"
        assert firewall["detail"]["rule_id"] == "fw.tcp"
        assert firewall["detail"]["reason_key"] == "fw_protocol_unknown"

    def test_any_trace_against_any_rule_still_decides(self, authenticated_client: TestClient, ngfw_mock):
        # An ``any`` rule imposes no protocol constraint, so "Любой" is decidable.
        ngfw_mock.state["fw_forward"] = (200, [_forward_rule("fw.any", "any", "drop")])
        firewall = _firewall_stage(_trace(authenticated_client, "any"))
        assert firewall["status"] == "block"
        assert firewall["detail"]["rule_id"] == "fw.any"

    def test_portless_protocol_ignores_a_port_restricted_rule(self, authenticated_client: TestClient, ngfw_mock):
        # An ``any``-protocol rule scoped to port 443 would block TCP:443 but
        # cannot apply to ICMP, which carries no L4 port.
        ngfw_mock.state["fw_forward"] = (
            200,
            [_forward_rule("fw.port443", "any", "drop", destination_ports=["443"])],
        )

        tcp = _firewall_stage(_trace(authenticated_client, "tcp", dst_port=443))
        assert tcp["status"] == "block"
        assert tcp["detail"]["rule_id"] == "fw.port443"

        icmp = _firewall_stage(_trace(authenticated_client, "icmp", dst_port=443))
        assert icmp["status"] == "pass"
        assert icmp["detail"]["reason_key"] == "fw_default_allow"


class TestNatAndPreFilterProtocol:
    def test_dnat_any_trace_against_tcp_rule_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_dnat"] = (
            200,
            [
                {
                    "id": "dnat.tcp",
                    "action": "dnat",
                    "protocol": "protocol.tcp",
                    "destinations": [{"addresses": ["any"]}],
                    "destination_ports": ["any"],
                    "change_destination_address": "192.0.2.254",
                }
            ],
        )
        response = _trace(authenticated_client, "any")
        assert response.status_code == 200
        dnat = next(stage for stage in response.json()["stages"] if stage["key"] == "dnat")
        assert dnat["status"] == "unknown"
        assert dnat["detail"]["reason_key"] == "fw_protocol_unknown"

    def test_pre_filter_any_trace_against_tcp_rule_is_unknown(self, authenticated_client: TestClient, ngfw_mock):
        ngfw_mock.state["fw_pre_filter"] = (
            200,
            (
                '"Rule type";"Protocol";"Source IP-address";"Source port";'
                '"Destination IP-address";"Destination port";"TCP-flags";'
                '"TCP-flags to blocking";"Packet length, bytes";"Comment";"Enabled"\r\n'
                '"drop_rules";"tcp";"None";"None";"None";'
                '"None";"";"";"None";"proto test";"Enabled"\r\n'
            ),
        )
        response = _trace(authenticated_client, "any")
        assert response.status_code == 200
        pre_filter = next(stage for stage in response.json()["stages"] if stage["key"] == "pre_filter")
        assert pre_filter["status"] == "unknown"
        assert pre_filter["detail"]["reason_key"] == "pre_filter_protocol_unknown"

    def test_pre_filter_portless_ignores_port_restricted_rule(self, authenticated_client: TestClient, ngfw_mock):
        # A port-443 drop rule cannot apply to ICMP; the pre-filter stage passes.
        ngfw_mock.state["fw_pre_filter"] = (
            200,
            (
                '"Rule type";"Protocol";"Source IP-address";"Source port";'
                '"Destination IP-address";"Destination port";"TCP-flags";'
                '"TCP-flags to blocking";"Packet length, bytes";"Comment";"Enabled"\r\n'
                '"drop_rules";"None";"None";"None";"None";'
                '"443";"";"";"None";"port test";"Enabled"\r\n'
            ),
        )
        response = _trace(authenticated_client, "icmp", dst_port=443)
        assert response.status_code == 200
        pre_filter = next(stage for stage in response.json()["stages"] if stage["key"] == "pre_filter")
        assert pre_filter["status"] == "pass"
        assert pre_filter["detail"]["reason_key"] == "pre_filter_no_matching_rule"

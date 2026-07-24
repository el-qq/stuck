"""Unit truth table for the tri-state firewall protocol matcher.

``protocol_match_state`` returns ``True`` (rule certainly applies to the traced
protocol), ``False`` (certainly does not) or ``None`` (undetermined — the stage
must become ``unknown`` per AGENTS.md invariant 7). NGFW stores rule protocols
as ``protocol.<name>`` or ``any``; hardware rows use IANA numbers. The traced
value is one of any/ah/esp/gre/icmp/tcp/udp/tcp_udp.
"""

import pytest

from app.domain.trace.port_matching import (
    canonical_protocol,
    protocol_is_portless,
    protocol_match_state,
)

_SPECIFIC = ["ah", "esp", "gre", "icmp", "tcp", "udp"]


@pytest.mark.parametrize("requested", ["any", *_SPECIFIC, "tcp_udp"])
def test_any_rule_always_matches(requested):
    # An ``any`` rule imposes no protocol constraint, whatever the request.
    for rule in ("any", "protocol.any", ""):
        assert protocol_match_state(rule, requested) is True


@pytest.mark.parametrize("rule", [*_SPECIFIC, "tcp_udp"])
def test_any_request_against_specific_rule_is_undetermined(rule):
    # "Любой" honestly cannot claim a verdict from a protocol-specific rule.
    assert protocol_match_state(f"protocol.{rule}", "any") is None


@pytest.mark.parametrize("proto", _SPECIFIC)
def test_specific_rule_matches_same_specific_request(proto):
    assert protocol_match_state(f"protocol.{proto}", proto) is True


@pytest.mark.parametrize(
    ("rule", "requested"),
    [
        ("protocol.tcp", "udp"),
        ("protocol.udp", "tcp"),
        ("protocol.icmp", "tcp"),
        ("protocol.gre", "esp"),
        ("protocol.ah", "esp"),
        ("protocol.tcp", "icmp"),
        ("protocol.tcp_udp", "icmp"),
        ("protocol.tcp_udp", "gre"),
    ],
)
def test_distinct_specific_protocols_do_not_match(rule, requested):
    assert protocol_match_state(rule, requested) is False


@pytest.mark.parametrize("requested", ["tcp", "udp"])
def test_tcp_udp_rule_covers_both_members(requested):
    # A "TCP/UDP" rule is a superset: a concrete tcp or udp request is inside it.
    assert protocol_match_state("protocol.tcp_udp", requested) is True
    assert protocol_match_state("tcp/udp", requested) is True


def test_tcp_udp_rule_matches_tcp_udp_request():
    assert protocol_match_state("protocol.tcp_udp", "tcp_udp") is True


@pytest.mark.parametrize("rule", ["protocol.tcp", "protocol.udp"])
def test_tcp_udp_request_against_single_member_rule_is_undetermined(rule):
    # The request may be the other member, so the single-member rule is unsure.
    assert protocol_match_state(rule, "tcp_udp") is None


@pytest.mark.parametrize(
    ("number", "name"),
    [("1", "icmp"), ("6", "tcp"), ("17", "udp"), ("47", "gre"), ("50", "esp"), ("51", "ah")],
)
def test_iana_numeric_rule_protocols(number, name):
    assert protocol_match_state(number, name) is True
    other = "udp" if name != "udp" else "tcp"
    assert protocol_match_state(number, other) is False


@pytest.mark.parametrize("requested", [*_SPECIFIC, "tcp_udp"])
def test_unrecognized_vendor_token_is_undetermined(requested):
    # An unknown rule protocol must never be guessed into a verdict.
    assert protocol_match_state("protocol.sctp", requested) is None
    assert protocol_match_state("2048", requested) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("protocol.tcp", "tcp"),
        ("PROTOCOL.TCP", "tcp"),
        ("6", "tcp"),
        ("51", "ah"),
        ("tcp/udp", "tcp_udp"),
        ("tcpudp", "tcp_udp"),
        ("", "any"),
        ("protocol.any", "any"),
        ("protocol.sctp", "sctp"),
    ],
)
def test_canonical_protocol_normalization(raw, expected):
    assert canonical_protocol(raw) == expected


@pytest.mark.parametrize(
    ("proto", "portless"),
    [
        ("icmp", True),
        ("ah", True),
        ("esp", True),
        ("gre", True),
        ("tcp", False),
        ("udp", False),
        ("tcp_udp", False),
        ("any", False),
        ("protocol.icmp", True),
        ("1", True),
    ],
)
def test_portless_classification(proto, portless):
    assert protocol_is_portless(proto) is portless

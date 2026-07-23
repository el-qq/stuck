"""First-match DNAT and SNAT evaluation for the local trace pipeline."""

from __future__ import annotations

from typing import Any, Optional

from ...ngfw import schemas as S
from ..binding_pool import RulesSnapshot
from .contracts import stage
from .address_matching import (
    _dests_block_match_state,
    _single_nat_ip,
    _sources_block_match_state,
    _unknown_object_reason,
)
from .port_matching import has_specific_values, ports_match_state, protocol_matches, single_nat_port


def evaluate_dnat(
    snapshot: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> tuple[dict[str, Any], Optional[str], int]:
    """Evaluate the first possible DNAT rule and return its effective target."""
    if not snapshot.fw_state.enabled:
        return (
            stage("dnat", "skip", {"module_enabled": False, "reason_key": "dnat_disabled"}),
            destination_ip,
            dst_port,
        )
    for rule in snapshot.fw_dnat:
        match_state = _rule_match_state(
            rule, snapshot, user_tokens, source_ip, destination_ip, host, protocol, dst_port
        )
        if match_state is False:
            continue
        detail = _rule_detail(rule)
        if match_state is None:
            detail["reason_key"] = _unknown_match_reason(
                rule, snapshot, user_tokens, source_ip, destination_ip, host, dst_port
            )
            return stage("dnat", "unknown", detail), destination_ip, dst_port
        if _conditions_unknown(rule, dnat=True):
            detail["reason_key"] = "dnat_conditions_unknown"
            return stage("dnat", "unknown", detail), destination_ip, dst_port
        if detail["action"] == "accept":
            detail["reason_key"] = "dnat_accept"
            return stage("dnat", "pass", detail), destination_ip, dst_port
        if detail["action"] != "dnat":
            detail["reason_key"] = "dnat_action_unknown"
            return stage("dnat", "unknown", detail), destination_ip, dst_port

        changed_ip = (
            _single_nat_ip(rule.change_destination_address, snapshot.aliases)
            if rule.change_destination_address
            else destination_ip
        )
        changed_port = (
            single_nat_port(rule.change_destination_port, snapshot.aliases)
            if rule.change_destination_port
            else dst_port
        )
        if changed_ip is None or changed_port is None:
            detail["reason_key"] = "dnat_transform_unknown"
            return stage("dnat", "unknown", detail), destination_ip, dst_port
        detail.update(
            {
                "translated_destination_ip": changed_ip,
                "translated_destination_port": changed_port,
                "reason_key": "dnat_applied",
            }
        )
        return stage("dnat", "applied", detail), changed_ip, changed_port
    return (
        stage("dnat", "pass", {"module_enabled": True, "reason_key": "dnat_no_matching_rule"}),
        destination_ip,
        dst_port,
    )


def evaluate_snat(
    snapshot: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> dict[str, Any]:
    """Evaluate the first possible SNAT rule after firewall and IPS stages."""
    if not snapshot.fw_state.enabled:
        return stage("snat", "skip", {"module_enabled": False, "reason_key": "snat_disabled"})
    for rule in snapshot.fw_snat:
        match_state = _rule_match_state(
            rule, snapshot, user_tokens, source_ip, destination_ip, host, protocol, dst_port
        )
        if match_state is False:
            continue
        detail = _rule_detail(rule)
        if match_state is None:
            detail["reason_key"] = _unknown_match_reason(
                rule, snapshot, user_tokens, source_ip, destination_ip, host, dst_port
            )
            return stage("snat", "unknown", detail)
        if _conditions_unknown(rule, dnat=False):
            detail["reason_key"] = "snat_conditions_unknown"
            return stage("snat", "unknown", detail)
        if detail["action"] == "accept":
            detail["reason_key"] = "snat_accept"
            return stage("snat", "pass", detail)
        if detail["action"] != "snat":
            detail["reason_key"] = "snat_action_unknown"
            return stage("snat", "unknown", detail)
        changed_ip = _single_nat_ip(rule.change_source_address, snapshot.aliases)
        if changed_ip is None:
            detail["reason_key"] = "snat_transform_unknown"
            return stage("snat", "unknown", detail)
        detail.update({"translated_source_ip": changed_ip, "reason_key": "snat_applied"})
        return stage("snat", "applied", detail)

    if snapshot.fw_settings.automatic_snat_enabled:
        return stage("snat", "active", {"module_enabled": True, "reason_key": "snat_automatic_active"})
    return stage("snat", "pass", {"module_enabled": True, "reason_key": "snat_no_matching_rule"})


def _rule_match_state(
    rule: S.FirewallRule,
    snapshot: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> Optional[bool]:
    destination_match = _dests_block_match_state(rule, snapshot.aliases, destination_ip, host)
    ports_match = ports_match_state(rule.destination_ports, snapshot.aliases, dst_port)
    if (
        not rule.enabled
        or not protocol_matches(rule.protocol, protocol)
        or destination_match is False
        or ports_match is False
    ):
        return False
    source_match = _sources_block_match_state(rule, user_tokens, source_ip, snapshot.aliases)
    if source_match is False:
        return False
    if destination_match is None or ports_match is None:
        return None
    return source_match


def _conditions_unknown(rule: S.FirewallRule, *, dnat: bool) -> bool:
    return (
        has_specific_values(rule.source_ports)
        or has_specific_values(rule.timetable)
        or (dnat and rule.incoming_interface not in ("", "any"))
        or (not dnat and rule.outgoing_interface not in ("", "any"))
    )


def _rule_detail(rule: S.FirewallRule) -> dict[str, Any]:
    return {
        "rule_id": str(rule.id),
        "rule_name": rule.comment or None,
        "action": (rule.action or "accept").lower(),
        "module_enabled": True,
    }


def _unknown_match_reason(
    rule: S.FirewallRule,
    snapshot: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    dst_port: int,
) -> str:
    """Keep the prior first-match explanation for an undecidable NAT rule."""
    destination_match = _dests_block_match_state(rule, snapshot.aliases, destination_ip, host)
    source_match = _sources_block_match_state(rule, user_tokens, source_ip, snapshot.aliases)
    if destination_match is None:
        return _unknown_object_reason(address=destination_ip)
    if source_match is None and source_ip is None:
        return "source_ip_unknown"
    if source_match is None:
        return "fw_object_unknown"
    # The caller only reaches here when the port state is unknown.
    _ = dst_port
    return "fw_port_unknown"

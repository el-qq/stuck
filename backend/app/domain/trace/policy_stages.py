"""Content-filter and firewall-policy stages of a local traffic trace."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from ...ngfw import schemas as S
from ..binding_pool import RulesSnapshot
from .contracts import stage
from .address_matching import (
    _cf_rule_applies_to_user,
    _dests_block_match_state,
    _is_ngfw_address,
    _sources_block_match_state,
    _unknown_object_reason,
)
from .port_matching import has_specific_values, ports_match_state, protocol_matches


def evaluate_content_filter(
    snapshot: RulesSnapshot,
    url_categories: list[str],
    user_tokens: set[str],
    category_names: dict[str, str],
) -> dict[str, Any]:
    """Evaluate the first applicable content-filter rule for the traced URL."""
    if not snapshot.cf_state.enabled:
        return stage("content_filter", "skip", {"module_enabled": False, "reason_key": "cf_disabled"})
    categories = set(url_categories)
    for rule in snapshot.cf_rules:
        if not rule.enabled or not _cf_rule_applies_to_user(rule, user_tokens):
            continue
        if rule.http_methods and "GET" not in {method.upper() for method in rule.http_methods}:
            continue
        matched_category = None
        if rule.categories:
            intersection = set(rule.categories) & categories
            if not intersection:
                continue
            matched_category = next(iter(intersection))
        # The request does not carry a response body or a complete schedule.
        # An earlier rule with either condition can apply, so later rules may
        # not be used to infer an allow verdict.
        if rule.content_types or has_specific_values(rule.timetable):
            return stage(
                "content_filter",
                "unknown",
                {
                    "rule_id": str(rule.id),
                    "rule_name": rule.name or None,
                    "module_enabled": True,
                    "reason_key": "cf_conditions_unknown",
                },
            )
        access = (rule.access or "allow").lower()
        detail = {
            "rule_id": str(rule.id),
            "rule_name": rule.name or None,
            "action": access,
            "matched_category": category_names.get(matched_category, matched_category) if matched_category else None,
            "module_enabled": True,
        }
        if access in ("allow", "bump"):
            detail["reason_key"] = "cf_allowed"
            return stage("content_filter", "pass", detail)
        if access == "deny":
            detail["reason_key"] = "cf_category_blocked"
            return stage("content_filter", "block", detail)
        if access == "redirect":
            detail["redirect_url"] = rule.redirect_url
            detail["reason_key"] = "cf_redirect"
            return stage("content_filter", "block", detail)
        detail["reason_key"] = "cf_action_unknown"
        return stage("content_filter", "unknown", detail)

    return stage("content_filter", "pass", {"module_enabled": True, "reason_key": "cf_no_matching_rule"})


def evaluate_firewall(
    snapshot: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> tuple[dict[str, Any], Optional[S.FirewallRule]]:
    """Evaluate the selected INPUT/FORWARD chain using first-possible-match.

    A rule whose unprovided context may match becomes ``unknown`` immediately;
    it is unsafe to skip it and present the result of a later allow rule.
    """
    table = "input" if _is_ngfw_address(snapshot.ngfw_addresses, destination_ip) else "forward"
    rules = snapshot.fw_input if table == "input" else snapshot.fw_forward
    if not snapshot.fw_state.enabled:
        return (
            stage("firewall", "skip", {"module_enabled": False, "firewall_table": table, "reason_key": "fw_disabled"}),
            None,
        )

    for rule in rules:
        if not rule.enabled or not protocol_matches(rule.protocol, protocol):
            continue
        source_match = _sources_block_match_state(rule, user_tokens, source_ip, snapshot.aliases)
        if source_match is False:
            continue
        destination_match = _dests_block_match_state(rule, snapshot.aliases, destination_ip, host)
        if destination_match is False:
            continue
        ports_match = ports_match_state(rule.destination_ports, snapshot.aliases, dst_port)
        if ports_match is False:
            continue
        if source_match is None:
            return _unknown_rule_stage(
                rule,
                table,
                "source_ip_unknown" if source_ip is None else "fw_object_unknown",
            ), None
        if destination_match is None:
            return _unknown_rule_stage(rule, table, _unknown_object_reason(address=destination_ip)), None
        if ports_match is None:
            return _unknown_rule_stage(rule, table, "fw_port_unknown"), None
        if _unavailable_rule_context(rule):
            return _unknown_rule_stage(rule, table, "fw_conditions_unknown"), None

        action = (rule.action or "accept").lower()
        detail = {
            "rule_id": str(rule.id),
            "rule_name": rule.comment or None,
            "action": action,
            "module_enabled": True,
            "firewall_table": table,
        }
        if action == "accept":
            detail["reason_key"] = "fw_rule_accept"
            return stage("firewall", "pass", detail), rule
        if action in {"drop", "reject", "deny"}:
            detail["reason_key"] = "fw_rule_blocked"
            return stage("firewall", "block", detail), rule
        detail["reason_key"] = "fw_action_unknown"
        return stage("firewall", "unknown", detail), None

    if table == "forward" and (user_tokens or _source_in_lan(source_ip, snapshot.lan_networks)):
        return (
            stage(
                "firewall",
                "pass",
                {"module_enabled": True, "firewall_table": table, "reason_key": "fw_default_allow"},
            ),
            None,
        )
    return (
        stage(
            "firewall",
            "unknown",
            {"module_enabled": True, "firewall_table": table, "reason_key": "fw_default_policy_unknown"},
        ),
        None,
    )


def _unknown_rule_stage(rule: S.FirewallRule, table: str, reason_key: str) -> dict[str, Any]:
    return stage(
        "firewall",
        "unknown",
        {
            "rule_id": str(rule.id),
            "rule_name": rule.comment or None,
            "module_enabled": True,
            "firewall_table": table,
            "reason_key": reason_key,
        },
    )


def _unavailable_rule_context(rule: S.FirewallRule) -> bool:
    return (
        has_specific_values(rule.source_ports)
        or has_specific_values(rule.timetable)
        or rule.incoming_interface not in ("", "any")
        or rule.outgoing_interface not in ("", "any")
        or rule.hip_profiles
    )


def _source_in_lan(source_ip: Optional[str], lan_networks: list[str]) -> bool:
    """Return whether an address is provably in a LAN-side interface network."""
    if not source_ip or not lan_networks:
        return False
    try:
        source = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    for network in lan_networks:
        try:
            if source in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False

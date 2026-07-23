"""Early trace stages: NIC filter, packet pre-filter, shaping and DNS."""

from __future__ import annotations

import ipaddress
from typing import Any

from ...ngfw import schemas as S
from ..binding_pool import RulesSnapshot
from .address_matching import _alias_matches_target, _ip_equal, _raw_ip_matches
from .contracts import stage
from .port_matching import protocol_matches, raw_port_matches


def evaluate_hw_filter(snapshot: RulesSnapshot, source_ip: str | None, resolved_ip: str | None) -> dict[str, Any]:
    """Evaluate the active NIC drop list before any software policy stage.

    Hardware filtering has one active mode. Missing MAC/source/destination
    context is deliberately ``unknown`` whenever an enabled entry may match,
    preserving the ordered-pipeline fail-closed invariant.
    """
    if snapshot.hw_settings is None:
        return stage("hw_filter", "skip", {"module_enabled": False, "reason_key": "hw_not_supported"})

    mode = snapshot.hw_settings.mode
    rules_by_mode: dict[str, list[Any]] = {
        "mac": snapshot.hw_rules_mac,
        "src-ip": snapshot.hw_rules_src_ip,
        "dst-ip": snapshot.hw_rules_dst_ip,
        "src-and-dst-ip": snapshot.hw_rules_src_dst_ip,
    }
    enabled_rules = [rule for rule in rules_by_mode[mode] if rule.enabled]
    detail: dict[str, Any] = {"module_enabled": True, "hw_mode": mode}
    if not enabled_rules:
        detail["reason_key"] = "hw_no_matching_rule"
        return stage("hw_filter", "pass", detail)

    if mode == "mac":
        detail["reason_key"] = "hw_mac_unknown"
        return stage("hw_filter", "unknown", detail)

    needs_source = mode in ("src-ip", "src-and-dst-ip")
    needs_destination = mode in ("dst-ip", "src-and-dst-ip")
    if needs_source and source_ip is None:
        detail["reason_key"] = "hw_source_ip_unknown"
        return stage("hw_filter", "unknown", detail)
    if needs_destination and resolved_ip is None:
        detail["reason_key"] = "hw_destination_unknown"
        return stage("hw_filter", "unknown", detail)

    for rule in enabled_rules:
        source_matches = _ip_equal(rule.source_ip, source_ip) if needs_source else True
        destination_matches = _ip_equal(rule.destination_ip, resolved_ip) if needs_destination else True
        if source_matches and destination_matches:
            detail.update(
                {
                    "rule_id": str(rule.id),
                    "rule_name": rule.comment or None,
                    "action": "drop",
                    "reason_key": "hw_rule_blocked",
                }
            )
            return stage("hw_filter", "block", detail)

    detail["reason_key"] = "hw_no_matching_rule"
    return stage("hw_filter", "pass", detail)


def evaluate_rate_limit(snapshot: RulesSnapshot, user_tokens: set[str], ip: str | None, host: str) -> dict[str, Any]:
    if not snapshot.shaper_state.enabled:
        return stage("rate_limit", "skip", {"module_enabled": False, "reason_key": "rate_limit_disabled"})

    for rule in snapshot.shaper_rules:
        if not rule.enabled:
            continue
        rule_aliases = [str(alias).strip() for alias in rule.aliases if str(alias).strip()]
        matches = not rule_aliases
        for alias_id in rule_aliases:
            if alias_id.lower() == "any" or alias_id in user_tokens:
                matches = True
                break
            if _alias_matches_target(alias_id, snapshot.aliases, ip, host):
                matches = True
                break
        if not matches:
            continue
        speed = float(rule.speed_value)
        speed_value: int | float = int(speed) if speed.is_integer() else speed
        return stage(
            "rate_limit",
            "limited",
            {
                "rule_id": str(rule.id),
                "rule_name": rule.name or None,
                "action": "limit",
                "module_enabled": True,
                "speed_kbps": speed_value,
                "limit_scope": rule.apply_to,
                "reason_key": "rate_limit_applied",
            },
        )

    return stage("rate_limit", "pass", {"module_enabled": True, "reason_key": "rate_limit_no_matching_rule"})


def match_dns_zone(host: str, zones: list[S.DnsZone]) -> S.DnsZone | None:
    """Return the most-specific enabled local zone that covers ``host``."""
    best: S.DnsZone | None = None
    candidate = (host or "").lower().rstrip(".")
    for zone in zones:
        if not zone.enabled:
            continue
        name = zone.name.lower().strip().rstrip(".")
        if not name or (candidate != name and not candidate.endswith("." + name)):
            continue
        if best is None or len(name) > len(best.name.strip().rstrip(".")):
            best = zone
    return best


def evaluate_dns(snapshot: RulesSnapshot, host: str, resolved_ip: str | None) -> dict[str, Any]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return stage("dns", "skip", {"reason_key": "dns_not_required"})

    zone = match_dns_zone(host, snapshot.dns_zones)
    if zone is not None:
        # System DNS may disagree with an NGFW-local zone. Its answer must not
        # leak a private name upstream or be presented as the NGFW's answer.
        return stage(
            "dns",
            "unknown",
            {"rule_id": str(zone.id), "rule_name": zone.name, "reason_key": "dns_zone_unresolved"},
        )
    if resolved_ip is None:
        return stage("dns", "unknown", {"reason_key": "dns_lookup_failed"})
    return stage("dns", "resolved", {"reason_key": "dns_policy_unknown", "resolved_ip": resolved_ip})


def evaluate_pre_filter(
    snapshot: RulesSnapshot,
    source_ip: str | None,
    destination_ip: str | None,
    protocol: str,
    dst_port: int,
) -> dict[str, Any]:
    """Evaluate the ordered preliminary packet-blocking CSV snapshot."""
    if not snapshot.fw_state.enabled:
        return stage("pre_filter", "skip", {"module_enabled": False, "reason_key": "pre_filter_disabled"})
    for rule in snapshot.fw_pre_filter:
        if not rule.enabled or not protocol_matches(rule.protocol, protocol):
            continue
        if not _raw_ip_matches(rule.destination_address, destination_ip):
            continue
        if not raw_port_matches(rule.destination_port, dst_port):
            continue
        if rule.source_address and source_ip is None:
            return stage(
                "pre_filter",
                "unknown",
                {
                    "rule_id": rule.id,
                    "rule_name": rule.comment or None,
                    "action": "drop",
                    "module_enabled": True,
                    "reason_key": "pre_filter_source_unknown",
                },
            )
        if not _raw_ip_matches(rule.source_address, source_ip):
            continue
        if rule.source_port or rule.tcp_flags or rule.blocked_tcp_flags or rule.packet_length:
            return stage(
                "pre_filter",
                "unknown",
                {
                    "rule_id": rule.id,
                    "rule_name": rule.comment or None,
                    "action": "drop",
                    "module_enabled": True,
                    "reason_key": "pre_filter_conditions_unknown",
                },
            )
        return stage(
            "pre_filter",
            "block",
            {
                "rule_id": rule.id,
                "rule_name": rule.comment or None,
                "action": "drop",
                "module_enabled": True,
                "reason_key": "pre_filter_blocked",
            },
        )
    return stage("pre_filter", "pass", {"module_enabled": True, "reason_key": "pre_filter_no_matching_rule"})

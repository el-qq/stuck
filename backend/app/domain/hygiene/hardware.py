"""Hygiene checks for flat, hardware-filter drop lists."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..binding_pool import RulesSnapshot
from .models import HygieneFinding

_LIST_MODES: tuple[str, ...] = ("mac", "src-ip", "dst-ip", "src-and-dst-ip")


def analyze_hardware(snapshot: RulesSnapshot) -> list[HygieneFinding]:
    """Report inactive-list rules and duplicate targets in the active list."""
    if snapshot.hw_settings is None:
        return []
    active_mode = snapshot.hw_settings.mode
    findings = _inactive_list_findings(snapshot, active_mode)
    findings.extend(_duplicate_findings(snapshot, active_mode))
    return findings


def rules_for_mode(snapshot: RulesSnapshot, mode: str) -> list[Any]:
    return {
        "mac": snapshot.hw_rules_mac,
        "src-ip": snapshot.hw_rules_src_ip,
        "dst-ip": snapshot.hw_rules_dst_ip,
        "src-and-dst-ip": snapshot.hw_rules_src_dst_ip,
    }[mode]


def match_key(mode: str, rule: Any) -> str:
    """Normalize a hardware rule target within its mode-specific list."""
    if mode == "mac":
        return (rule.mac or "").strip().lower()
    if mode == "src-ip":
        return str(ipaddress.ip_address(rule.source_ip))
    if mode == "dst-ip":
        return str(ipaddress.ip_address(rule.destination_ip))
    return f"{ipaddress.ip_address(rule.source_ip)}>{ipaddress.ip_address(rule.destination_ip)}"


def _inactive_list_findings(snapshot: RulesSnapshot, active_mode: str) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    for mode in _LIST_MODES:
        if mode == active_mode:
            continue
        enabled = [(index + 1, rule) for index, rule in enumerate(rules_for_mode(snapshot, mode)) if rule.enabled]
        if not enabled:
            continue
        (first_position, first_rule), *remaining = enabled
        findings.append(
            HygieneFinding(
                kind="hw_inactive",
                severity="warning",
                tier="certain",
                table="hw_filter",
                rule_id=str(first_rule.id),
                rule_name=first_rule.comment or None,
                rule_position=first_position,
                reason_key="hygiene_hw_inactive",
                related=[
                    {"id": str(rule.id), "name": rule.comment or None, "position": position}
                    for position, rule in remaining
                ],
                extra={"inactive_count": len(enabled), "list_mode": mode, "active_mode": active_mode},
            )
        )
    return findings


def _duplicate_findings(snapshot: RulesSnapshot, active_mode: str) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    seen: dict[str, tuple[int, Any]] = {}
    for index, rule in enumerate(rules_for_mode(snapshot, active_mode)):
        if not rule.enabled:
            continue
        key = match_key(active_mode, rule)
        if key not in seen:
            seen[key] = (index + 1, rule)
            continue
        first_position, first_rule = seen[key]
        findings.append(
            HygieneFinding(
                kind="redundant",
                severity="info",
                tier="certain",
                table="hw_filter",
                rule_id=str(rule.id),
                rule_name=rule.comment or None,
                rule_position=index + 1,
                reason_key="hygiene_hw_duplicate",
                related=[{"id": str(first_rule.id), "name": first_rule.comment or None, "position": first_position}],
            )
        )
    return findings

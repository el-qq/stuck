"""Coverage analysis for ordered NGFW firewall chains."""

from __future__ import annotations

from ...ngfw import schemas as S
from .models import Dimension, HygieneFinding, RuleFacts, Tier

_ANY_TOKENS = {"", "any"}


def analyze_chain(table: str, rules: list[S.FirewallRule]) -> list[HygieneFinding]:
    """Find broad, unreachable, shadowed and redundant rules in one chain."""
    findings: list[HygieneFinding] = []
    facts = [rule_facts(rule, index + 1) for index, rule in enumerate(rules)]
    enabled = [fact for fact in facts if fact.rule.enabled]

    findings.extend(_overly_broad_findings(table, enabled))
    catch_all_at = _first_catch_all(enabled)
    shadowed_by_catch_all = _append_unreachable_finding(findings, table, enabled, catch_all_at)
    findings.extend(_pairwise_findings(table, enabled, shadowed_by_catch_all))
    return findings


def rule_facts(rule: S.FirewallRule, position: int) -> RuleFacts:
    return RuleFacts(
        rule=rule,
        position=position,
        protocol=protocol_dimension(rule.protocol),
        sources=address_dimension(rule.sources),
        destinations=address_dimension(rule.destinations),
        dst_ports=port_dimension(rule.destination_ports),
        has_narrowing=has_narrowing_conditions(rule),
    )


def address_dimension(blocks: list[S.SourceDest]) -> Dimension:
    """Represent empty/``any`` blocks, literals, and undecidable blocks safely."""
    if not blocks:
        return Dimension(any=True, tokens=frozenset(), opaque=False)
    if len(blocks) > 1 or any(block.addresses_negate for block in blocks):
        return Dimension(any=False, tokens=frozenset(), opaque=True)
    tokens = {str(address).strip().lower() for address in blocks[0].addresses if str(address).strip()}
    if not tokens or tokens & _ANY_TOKENS:
        return Dimension(any=True, tokens=frozenset(), opaque=False)
    return Dimension(any=False, tokens=frozenset(tokens), opaque=False)


def port_dimension(port_ids: list[str]) -> Dimension:
    tokens = {str(port).strip().lower() for port in port_ids if str(port).strip()}
    if not tokens or tokens & _ANY_TOKENS:
        return Dimension(any=True, tokens=frozenset(), opaque=False)
    return Dimension(any=False, tokens=frozenset(tokens), opaque=False)


def protocol_dimension(protocol: str) -> Dimension:
    normalized = (protocol or "any").strip().lower()
    if normalized in ("any", "protocol.any", ""):
        return Dimension(any=True, tokens=frozenset(), opaque=False)
    aliases = {"6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp"}
    return Dimension(any=False, tokens=frozenset({aliases.get(normalized, normalized)}), opaque=False)


def has_narrowing_conditions(rule: S.FirewallRule) -> bool:
    return bool(
        has_specific_values(rule.source_ports)
        or has_specific_values(rule.timetable)
        or rule.incoming_interface not in ("", "any")
        or rule.outgoing_interface not in ("", "any")
        or rule.hip_profiles
    )


def has_specific_values(values: list[str]) -> bool:
    normalized = {str(value).strip().lower() for value in values if str(value).strip()}
    return bool(normalized - {"any"})


def coverage(earlier: RuleFacts, later: RuleFacts) -> Tier | None:
    """Return the certainty tier when ``earlier`` fully covers ``later``."""
    tier: Tier = "certain"
    for earlier_dimension, later_dimension in (
        (earlier.protocol, later.protocol),
        (earlier.sources, later.sources),
        (earlier.destinations, later.destinations),
        (earlier.dst_ports, later.dst_ports),
    ):
        result = earlier_dimension.covers(later_dimension)
        if result is None:
            return None
        if result == "possible":
            tier = "possible"
    return "possible" if earlier.has_narrowing else tier


def rule_reference(facts: RuleFacts) -> dict:
    return {"id": str(facts.rule.id), "name": facts.rule.comment or None, "position": facts.position}


def _overly_broad_findings(table: str, rules: list[RuleFacts]) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    for index, facts in enumerate(rules):
        if not facts.is_universal or facts.action != "accept":
            continue
        preceding = rules[:index]
        severity = (
            "risk" if not preceding else "info" if any(rule.action != "accept" for rule in preceding) else "warning"
        )
        findings.append(
            HygieneFinding(
                kind="overly_broad",
                severity=severity,
                tier="certain",
                table=table,
                rule_id=str(facts.rule.id),
                rule_name=facts.rule.comment or None,
                rule_position=facts.position,
                reason_key="hygiene_overly_broad",
            )
        )
    return findings


def _first_catch_all(rules: list[RuleFacts]) -> int | None:
    return next((index for index, facts in enumerate(rules) if facts.is_universal), None)


def _append_unreachable_finding(
    findings: list[HygieneFinding], table: str, rules: list[RuleFacts], catch_all_at: int | None
) -> set[int]:
    if catch_all_at is None or catch_all_at + 1 >= len(rules):
        return set()
    catch_all = rules[catch_all_at]
    unreachable = rules[catch_all_at + 1 :]
    findings.append(
        HygieneFinding(
            kind="unreachable_after_any",
            severity="warning",
            tier="certain",
            table=table,
            rule_id=str(catch_all.rule.id),
            rule_name=catch_all.rule.comment or None,
            rule_position=catch_all.position,
            reason_key="hygiene_unreachable_after_any",
            related=[rule_reference(rule) for rule in unreachable],
            extra={"unreachable_count": len(unreachable)},
        )
    )
    return {id(rule) for rule in unreachable}


def _pairwise_findings(table: str, rules: list[RuleFacts], excluded: set[int]) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    for later_index, later in enumerate(rules):
        if id(later) in excluded:
            continue
        for earlier in rules[:later_index]:
            if id(earlier) in excluded:
                continue
            tier = coverage(earlier, later)
            if tier is None:
                continue
            same_action = earlier.action == later.action
            findings.append(
                HygieneFinding(
                    kind="redundant" if same_action else "shadowed",
                    severity="info" if same_action else "warning",
                    tier=tier,
                    table=table,
                    rule_id=str(later.rule.id),
                    rule_name=later.rule.comment or None,
                    rule_position=later.position,
                    reason_key="hygiene_redundant" if same_action else "hygiene_shadowed",
                    related=[rule_reference(earlier)],
                )
            )
            break
    return findings

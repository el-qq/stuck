"""Rule-hygiene analysis — static, read-only checks over a rules snapshot.

Unlike a single trace (one packet's journey), hygiene inspects the *structure* of
an ordered firewall table and reports problems no individual trace can reveal:

* ``shadowed``    — an earlier terminal rule fully covers this rule but has a
                    DIFFERENT action, so this rule's intended verdict never runs.
* ``redundant``   — an earlier rule fully covers this rule with the SAME action,
                    so this rule is dead weight.
* ``unreachable_after_any`` — a universal catch-all precedes a region of the
                    chain, so every rule after it is dead. Reported once, grouped.
* ``overly_broad``— a universal ``any→any`` rule that accepts traffic; a posture
                    risk rather than a bug (its own ``severity`` is ``risk``).

Soundness mandate (mirrors trace-engine invariant #7): we only ever claim a
*certain* finding when coverage is provable from concrete, decidable data. When a
dimension is opaque — a negated address set, multiple AND-combined address
blocks, or a narrowing condition we cannot compare (source port / interface /
schedule / HIP) — the finding is downgraded to the ``possible`` tier, never a
false certainty. Address / port coverage uses literal token-superset containment
(``A ⊇ B`` iff every token B references is also referenced by A); this can only
UNDER-report (e.g. it will not yet see ``10.0.0.0/8`` covering ``10.1.0.0/16``),
never over-report. CIDR/interval containment is a future refinement.

Strictly read-only: a pure function of the snapshot. No NGFW calls, no mutation.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from ..ngfw import schemas as S
from .binding_pool import RulesSnapshot

# Firewall actions are terminal first-match: reaching a matching rule ends
# evaluation. So any earlier rule that fully covers a later one shadows it.
_ANY_TOKENS = {"", "any"}

Tier = Literal["certain", "possible"]

# The two ordered firewall chains analysed in v1. Each is evaluated on its own —
# a rule in FORWARD can never shadow a rule in INPUT.
_CHAINS: tuple[str, ...] = ("fw_forward", "fw_input")


@dataclass(frozen=True)
class _Dim:
    """One comparable dimension of a rule: a universal 'any', a concrete token
    set, or opaque (undecidable → coverage cannot be proven)."""

    any: bool
    tokens: frozenset[str]
    opaque: bool

    def covers(self, other: "_Dim") -> Optional[Tier]:
        """Does this dimension cover ``other``? ``certain`` / ``possible`` / None."""
        if self.any:
            return "certain"
        if self.opaque or other.opaque:
            return "possible"
        if other.any:
            # A concrete set cannot cover 'any' (something is outside it).
            return None
        return "certain" if self.tokens >= other.tokens else None


def _address_dim(blocks: list[S.SourceDest]) -> _Dim:
    """Reduce a rule's source/destination blocks to a comparable dimension.

    Empty → any. A negated set or more than one AND-combined block is opaque
    (their exact reach is not safely decidable with literal tokens). Otherwise
    the union of the single block's address tokens (addresses are OR-combined).
    """
    if not blocks:
        return _Dim(any=True, tokens=frozenset(), opaque=False)
    if len(blocks) > 1 or any(b.addresses_negate for b in blocks):
        return _Dim(any=False, tokens=frozenset(), opaque=True)
    tokens = {str(a).strip().lower() for a in blocks[0].addresses if str(a).strip()}
    if not tokens or tokens & _ANY_TOKENS:
        return _Dim(any=True, tokens=frozenset(), opaque=False)
    return _Dim(any=False, tokens=frozenset(tokens), opaque=False)


def _port_dim(port_ids: list[str]) -> _Dim:
    tokens = {str(p).strip().lower() for p in port_ids if str(p).strip()}
    if not tokens or tokens & _ANY_TOKENS:
        return _Dim(any=True, tokens=frozenset(), opaque=False)
    return _Dim(any=False, tokens=frozenset(tokens), opaque=False)


def _protocol_dim(proto: str) -> _Dim:
    p = (proto or "any").strip().lower()
    if p in ("any", "protocol.any", ""):
        return _Dim(any=True, tokens=frozenset(), opaque=False)
    if p in ("6", "tcp"):
        p = "tcp"
    elif p in ("17", "udp"):
        p = "udp"
    return _Dim(any=False, tokens=frozenset({p}), opaque=False)


@dataclass(frozen=True)
class _Facts:
    """Everything the analyser needs about one rule, precomputed once."""

    rule: S.FirewallRule
    position: int  # 1-based index in the full chain (incl. disabled rules)
    protocol: _Dim
    sources: _Dim
    destinations: _Dim
    dst_ports: _Dim
    # A rule with a narrowing condition matches only a SUBSET of its address/port
    # reach, so it can never *certainly* cover another rule — coverage degrades
    # to 'possible'.
    has_narrowing: bool

    @property
    def action(self) -> str:
        return (self.rule.action or "accept").lower()

    @property
    def is_universal(self) -> bool:
        """A true catch-all: every dimension is 'any' and nothing narrows it."""
        return (
            self.protocol.any
            and self.sources.any
            and self.destinations.any
            and self.dst_ports.any
            and not self.has_narrowing
        )


def _narrowing(rule: S.FirewallRule) -> bool:
    return bool(
        _has_specific(rule.source_ports)
        or _has_specific(rule.timetable)
        or (rule.incoming_interface not in ("", "any"))
        or (rule.outgoing_interface not in ("", "any"))
        or rule.hip_profiles
    )


def _has_specific(values: list[str]) -> bool:
    normalized = {str(v).strip().lower() for v in values if str(v).strip()}
    return bool(normalized - {"any"})


def _facts(rule: S.FirewallRule, position: int) -> _Facts:
    return _Facts(
        rule=rule,
        position=position,
        protocol=_protocol_dim(rule.protocol),
        sources=_address_dim(rule.sources),
        destinations=_address_dim(rule.destinations),
        dst_ports=_port_dim(rule.destination_ports),
        has_narrowing=_narrowing(rule),
    )


def _coverage(a: _Facts, b: _Facts) -> Optional[Tier]:
    """Does rule ``a`` cover every packet rule ``b`` would match? Sound: returns
    ``certain`` only when provable, ``possible`` when plausible-but-opaque, else
    None. ``a`` having a narrowing condition caps the result at ``possible``."""
    tier: Tier = "certain"
    for dim_a, dim_b in (
        (a.protocol, b.protocol),
        (a.sources, b.sources),
        (a.destinations, b.destinations),
        (a.dst_ports, b.dst_ports),
    ):
        result = dim_a.covers(dim_b)
        if result is None:
            return None
        if result == "possible":
            tier = "possible"
    if a.has_narrowing:
        tier = "possible"
    return tier


@dataclass
class HygieneFinding:
    kind: str  # shadowed | redundant | unreachable_after_any | overly_broad
    severity: str  # warning | info | risk
    tier: Tier
    table: str
    rule_id: str
    rule_name: Optional[str]
    rule_position: int
    reason_key: str
    related: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "tier": self.tier,
            "table": self.table,
            "reason_key": self.reason_key,
            "rule": {"id": self.rule_id, "name": self.rule_name, "position": self.rule_position},
            "related": self.related,
            **({"extra": self.extra} if self.extra else {}),
        }


def _rule_ref(f: _Facts) -> dict:
    return {"id": str(f.rule.id), "name": f.rule.comment or None, "position": f.position}


def _analyze_chain(table: str, rules: list[S.FirewallRule]) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    # 1-based positions over the FULL chain; only enabled rules can match, so
    # only they participate in reachability, but positions stay faithful.
    facts = [_facts(r, i + 1) for i, r in enumerate(rules)]
    enabled = [f for f in facts if f.rule.enabled]

    # Pass A — overly-broad universal accepts. Severity depends on CONTEXT: an
    # any-any accept is what actually grants network access, so
    #   * nothing enabled before it  → risk    (ALL traffic allowed, unconditionally);
    #   * enabled drops before it    → info    (the common "deny exceptions,
    #                                           allow the rest" tail — deliberate);
    #   * only accepts before it     → warning (broad allow with no exception
    #                                           carved out anywhere — review it).
    for idx, f in enumerate(enabled):
        if f.is_universal and f.action == "accept":
            before = enabled[:idx]
            if not before:
                severity = "risk"
            elif any(b.action != "accept" for b in before):
                severity = "info"
            else:
                severity = "warning"
            findings.append(
                HygieneFinding(
                    kind="overly_broad",
                    severity=severity,
                    tier="certain",
                    table=table,
                    rule_id=str(f.rule.id),
                    rule_name=f.rule.comment or None,
                    rule_position=f.position,
                    reason_key="hygiene_overly_broad",
                )
            )

    # Pass B — the first universal terminal rule makes everything after it dead.
    # Report that ONCE (grouped), and exclude those rules from the pairwise scan.
    catch_all_at: Optional[int] = None
    for idx, f in enumerate(enabled):
        if f.is_universal:
            catch_all_at = idx
            break
    shadowed_by_catch_all: set[int] = set()
    if catch_all_at is not None and catch_all_at + 1 < len(enabled):
        catch_all = enabled[catch_all_at]
        after = enabled[catch_all_at + 1 :]
        shadowed_by_catch_all = {id(f) for f in after}
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
                related=[_rule_ref(f) for f in after],
                extra={"unreachable_count": len(after)},
            )
        )

    # Pass C — pairwise shadow / redundant for rules not already explained by a
    # catch-all. Each covered rule is attributed to its EARLIEST coverer.
    for j, b in enumerate(enabled):
        if id(b) in shadowed_by_catch_all:
            continue
        for a in enabled[:j]:
            if id(a) in shadowed_by_catch_all:
                continue
            tier = _coverage(a, b)
            if tier is None:
                continue
            same_action = a.action == b.action
            findings.append(
                HygieneFinding(
                    kind="redundant" if same_action else "shadowed",
                    severity="info" if same_action else "warning",
                    tier=tier,
                    table=table,
                    rule_id=str(b.rule.id),
                    rule_name=b.rule.comment or None,
                    rule_position=b.position,
                    reason_key="hygiene_redundant" if same_action else "hygiene_shadowed",
                    related=[_rule_ref(a)],
                )
            )
            break  # earliest coverer only

    return findings


_HW_LISTS: tuple[str, ...] = ("mac", "src-ip", "dst-ip", "src-and-dst-ip")


def _hw_rules(snap: RulesSnapshot, mode: str) -> list:
    return {
        "mac": snap.hw_rules_mac,
        "src-ip": snap.hw_rules_src_ip,
        "dst-ip": snap.hw_rules_dst_ip,
        "src-and-dst-ip": snap.hw_rules_src_dst_ip,
    }[mode]


def _hw_match_key(mode: str, rule) -> str:
    """Normalized identity of a rule's match target inside one list."""
    if mode == "mac":
        return (rule.mac or "").strip().lower()
    if mode == "src-ip":
        return str(ipaddress.ip_address(rule.source_ip))
    if mode == "dst-ip":
        return str(ipaddress.ip_address(rule.destination_ip))
    return f"{ipaddress.ip_address(rule.source_ip)}>{ipaddress.ip_address(rule.destination_ip)}"


def _analyze_hw(snap: RulesSnapshot) -> list[HygieneFinding]:
    """Hardware-filtering hygiene. Ordering-based checks do not apply (flat
    drop lists, one implicit action); what DOES matter:

    * ``hw_inactive`` — enabled rules configured in a list whose mode is NOT
      active silently do nothing (easy to miss in the console) → warning.
    * duplicates inside the ACTIVE list (same normalized address / pair) →
      ``redundant`` (info), attributed to the first occurrence.
    """
    if snap.hw_settings is None:
        return []  # the NGFW does not expose the feature — nothing to check
    active = snap.hw_settings.mode
    findings: list[HygieneFinding] = []

    for mode in _HW_LISTS:
        if mode == active:
            continue
        rules = _hw_rules(snap, mode)
        enabled = [(i + 1, r) for i, r in enumerate(rules) if r.enabled]
        if not enabled:
            continue
        (first_pos, first), *rest = enabled
        findings.append(
            HygieneFinding(
                kind="hw_inactive",
                severity="warning",
                tier="certain",
                table="hw_filter",
                rule_id=str(first.id),
                rule_name=first.comment or None,
                rule_position=first_pos,
                reason_key="hygiene_hw_inactive",
                related=[{"id": str(r.id), "name": r.comment or None, "position": pos} for pos, r in rest],
                extra={"inactive_count": len(enabled), "list_mode": mode, "active_mode": active},
            )
        )

    seen: dict[str, tuple[int, Any]] = {}
    for idx, rule in enumerate(_hw_rules(snap, active)):
        if not rule.enabled:
            continue
        key = _hw_match_key(active, rule)
        if key in seen:
            first_pos, first = seen[key]
            findings.append(
                HygieneFinding(
                    kind="redundant",
                    severity="info",
                    tier="certain",
                    table="hw_filter",
                    rule_id=str(rule.id),
                    rule_name=rule.comment or None,
                    rule_position=idx + 1,
                    reason_key="hygiene_hw_duplicate",
                    related=[{"id": str(first.id), "name": first.comment or None, "position": first_pos}],
                )
            )
        else:
            seen[key] = (idx + 1, rule)
    return findings


def analyze_snapshot(snap: RulesSnapshot) -> dict:
    """Run every hygiene check over ``snap`` and return the contract shape."""
    findings: list[HygieneFinding] = []
    for table in _CHAINS:
        findings.extend(_analyze_chain(table, getattr(snap, table)))
    findings.extend(_analyze_hw(snap))

    summary = {"total": len(findings), "risk": 0, "warning": 0, "info": 0, "possible": 0}
    for f in findings:
        summary[f.severity] += 1
        if f.tier == "possible":
            summary["possible"] += 1

    return {
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }

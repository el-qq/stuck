"""Internal models for sound, static firewall-rule hygiene checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ...ngfw import schemas as S

Tier = Literal["certain", "possible"]


@dataclass(frozen=True)
class Dimension:
    """A comparable rule dimension.

    A dimension is either universal, a concrete set of literal references, or
    opaque. Opaque dimensions deliberately lower a result to ``possible``:
    hygiene must never report an uncertain cover as certain.
    """

    any: bool
    tokens: frozenset[str]
    opaque: bool

    def covers(self, other: Dimension) -> Tier | None:
        if self.any:
            return "certain"
        if self.opaque or other.opaque:
            return "possible"
        if other.any:
            return None
        return "certain" if self.tokens >= other.tokens else None


@dataclass(frozen=True)
class RuleFacts:
    """Comparable properties of one firewall rule, computed once per chain."""

    rule: S.FirewallRule
    position: int
    protocol: Dimension
    sources: Dimension
    destinations: Dimension
    dst_ports: Dimension
    has_narrowing: bool

    @property
    def action(self) -> str:
        return (self.rule.action or "accept").lower()

    @property
    def is_universal(self) -> bool:
        return (
            self.protocol.any
            and self.sources.any
            and self.destinations.any
            and self.dst_ports.any
            and not self.has_narrowing
        )


@dataclass
class HygieneFinding:
    """One serializable hygiene result in the public API shape."""

    kind: str
    severity: str
    tier: Tier
    table: str
    rule_id: str
    rule_name: str | None
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

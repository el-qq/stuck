"""Protocol and port-condition matching for ordered trace stages."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ...ngfw import schemas as S

# IANA network-layer protocol numbers used by hardware-filter and native
# firewall rows (docs/source/docs-ru-ngfw-access-rules-api-firewall.md).
_IANA_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah"}
# Protocol tokens STUCK can reason about honestly. Anything else is a vendor
# extension we must not guess (fail to ``unknown``, never a verdict).
_KNOWN_PROTOCOLS = {"any", "tcp_udp", "ah", "esp", "gre", "icmp", "tcp", "udp"}
# L3/ICMP protocols carry no L4 port; destination-port conditions cannot apply.
_PORTLESS_PROTOCOLS = {"icmp", "ah", "esp", "gre"}


def canonical_protocol(value: str) -> str:
    """Normalize any rule/request protocol token to a canonical name.

    Handles the ``protocol.<name>`` object prefix, IANA numeric codes and the
    ``tcp/udp`` (TCP or UDP) spelling variants. Unrecognized tokens are returned
    lowercased so the caller can detect and refuse to guess them.
    """
    text = (value or "").strip().lower()
    text = text.removeprefix("protocol.")
    if text in _IANA_PROTOCOLS:
        return _IANA_PROTOCOLS[text]
    if text in ("tcp_udp", "tcp/udp", "tcpudp"):
        return "tcp_udp"
    if text in ("any", ""):
        return "any"
    return text


def _expand_protocol(name: str) -> set[str]:
    """Expand a canonical protocol into the concrete protocols it covers."""
    return {"tcp", "udp"} if name == "tcp_udp" else {name}


def protocol_match_state(rule_protocol: str, requested_protocol: str) -> bool | None:
    """Tri-state match of an NGFW rule protocol against the traced protocol.

    ``None`` (undetermined) is returned when the outcome genuinely depends on
    context STUCK does not have — e.g. a request for ``any`` protocol facing a
    protocol-specific rule, an ambiguous ``tcp_udp`` request against a ``tcp``
    rule, or an unrecognized vendor token — so the stage becomes ``unknown``
    rather than fabricating a verdict (AGENTS.md invariant 7).
    """
    rule = canonical_protocol(rule_protocol)
    requested = canonical_protocol(requested_protocol)
    if rule == "any":
        return True
    if requested == "any":
        return None
    if rule not in _KNOWN_PROTOCOLS:
        return None
    rule_set = _expand_protocol(rule)
    requested_set = _expand_protocol(requested)
    if requested_set <= rule_set:
        return True
    if requested_set & rule_set:
        return None
    return False


def protocol_is_portless(requested_protocol: str) -> bool:
    """Return whether the traced protocol carries no L4 destination port."""
    return canonical_protocol(requested_protocol) in _PORTLESS_PROTOCOLS


def ports_match_state(port_ids: Iterable[str], aliases: dict[str, S.Alias], dst_port: int) -> bool | None:
    """Tri-state matching for a firewall/NAT destination-port condition."""
    ids = list(port_ids)
    if not ids:
        return True
    unresolved = False
    for alias_id in ids:
        if alias_id == "any":
            return True
        alias = aliases.get(alias_id)
        if not alias:
            raw_state = raw_port_state(alias_id, dst_port)
            if raw_state is True:
                return True
            if raw_state is None:
                unresolved = True
            continue

        states: list[bool | None] = []
        if alias.value is not None:
            states.append(port_value_state(alias.value, dst_port))
        if alias.start is not None or alias.end is not None:
            states.append(port_range_state(alias.start, alias.end, dst_port))
        states.extend(port_value_state(value, dst_port) for value in alias.values or [])
        if True in states:
            return True
        if not states or None in states:
            unresolved = True
    return None if unresolved else False


def raw_port_matches(spec: str | None, port: int) -> bool:
    """Match a literal preliminary-filter port or inclusive range."""
    if not spec:
        return True
    value = spec.strip()
    try:
        if "-" in value:
            start, end = (int(part.strip()) for part in value.split("-", 1))
            return start <= port <= end
        return int(value) == port
    except ValueError:
        return False


def single_nat_port(value: str | None, aliases: dict[str, S.Alias]) -> int | None:
    """Resolve a single DNAT port value without guessing from ranges/objects."""
    if not value:
        return None
    candidate: Any = value.strip()
    alias = aliases.get(str(candidate))
    if alias is not None:
        candidate = alias.value
    try:
        port = int(candidate)
    except TypeError, ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def has_specific_values(values: Iterable[str]) -> bool:
    """Return whether an API condition is narrower than unconditional ``any``."""
    normalized = {str(value).strip().lower() for value in values if str(value).strip()}
    return bool(normalized - {"any"})


def port_value_state(value: Any, dst_port: int) -> bool | None:
    try:
        port = int(value)
    except TypeError, ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return port == dst_port


def port_range_state(start: Any, end: Any, dst_port: int) -> bool | None:
    try:
        first, last = int(start), int(end)
    except TypeError, ValueError:
        return None
    if not 1 <= first <= last <= 65535:
        return None
    return first <= dst_port <= last


def raw_port_state(value: str, dst_port: int) -> bool | None:
    text = value.strip()
    if "-" in text:
        first, last = (part.strip() for part in text.split("-", 1))
        return port_range_state(first, last, dst_port)
    return port_value_state(text, dst_port)

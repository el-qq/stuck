"""Protocol and port-condition matching for ordered trace stages."""

from __future__ import annotations

from typing import Any, Iterable, Optional

from ...ngfw import schemas as S


def protocol_matches(rule_protocol: str, requested_protocol: str) -> bool:
    """Match an NGFW protocol representation against the traced protocol."""
    normalized = (rule_protocol or "any").lower()
    if normalized in ("any", "protocol.any", ""):
        return True
    if normalized in {"6", "tcp"}:
        return requested_protocol.lower() == "tcp"
    if normalized in {"17", "udp"}:
        return requested_protocol.lower() == "udp"
    return normalized.endswith(requested_protocol.lower())


def ports_match_state(port_ids: Iterable[str], aliases: dict[str, S.Alias], dst_port: int) -> Optional[bool]:
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

        states: list[Optional[bool]] = []
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


def raw_port_matches(spec: Optional[str], port: int) -> bool:
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


def single_nat_port(value: Optional[str], aliases: dict[str, S.Alias]) -> Optional[int]:
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


def port_value_state(value: Any, dst_port: int) -> Optional[bool]:
    try:
        port = int(value)
    except TypeError, ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return port == dst_port


def port_range_state(start: Any, end: Any, dst_port: int) -> Optional[bool]:
    try:
        first, last = int(start), int(end)
    except TypeError, ValueError:
        return None
    if not 1 <= first <= last <= 65535:
        return None
    return first <= dst_port <= last


def raw_port_state(value: str, dst_port: int) -> Optional[bool]:
    text = value.strip()
    if "-" in text:
        first, last = (part.strip() for part in text.split("-", 1))
        return port_range_state(first, last, dst_port)
    return port_value_state(text, dst_port)

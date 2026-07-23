"""Fail-closed user, address and alias matching for trace stages and export."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from ...ngfw import schemas as S
from ..binding_pool import RulesSnapshot


def _user_tokens(user: S.NgfwUser | None) -> set[str]:
    """Identity alias tokens the user matches in rule source/alias lists."""
    if user is None:
        return set()
    tokens: set[str] = {"any"}
    user_id = str(user.id)
    tokens.add(user_id)
    if not user_id.startswith("user."):
        tokens.add(f"user.id.{user_id}")
    if user.parent_id:
        parent_id = str(user.parent_id)
        tokens.add(parent_id)
        if not parent_id.startswith("group."):
            tokens.add(f"group.id.{parent_id}")
    return tokens


def _ip_in_alias(alias: S.Alias, ip: str | None, host: str) -> bool:
    """Return whether an address-like alias matches an IP address or host."""
    alias_type = (alias.type or "").lower()
    values: list[Any] = []
    if alias.value is not None:
        values.append(alias.value)
    if alias.values:
        values.extend(alias.values)

    if (
        "domain" in alias_type or (not alias_type and isinstance(alias.value, str) and _looks_like_domain(alias.value))
    ) and any(isinstance(value, str) and _host_matches_domain(host, value) for value in values):
        return True

    if ip is None:
        return False
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if alias.start is not None and alias.end is not None:
        try:
            if ipaddress.ip_address(str(alias.start)) <= target <= ipaddress.ip_address(str(alias.end)):
                return True
        except ValueError:
            pass

    for value in values:
        if not isinstance(value, str):
            continue
        try:
            if "/" in value and target in ipaddress.ip_network(value, strict=False):
                return True
            if ipaddress.ip_address(value) == target:
                return True
        except ValueError:
            continue
    return False


def _looks_like_domain(value: str) -> bool:
    if any(character.isalpha() for character in value) and "/" not in value:
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            return True
    return False


def _host_matches_domain(host: str, domain: str) -> bool:
    normalized_host = host.lower().rstrip(".")
    normalized_domain = domain.lower().lstrip("*.").rstrip(".")
    return normalized_host == normalized_domain or normalized_host.endswith("." + normalized_domain)


def _alias_matches_target(
    alias_id: str,
    aliases: dict[str, S.Alias],
    ip: str | None,
    host: str,
    seen: set[str] | None = None,
) -> bool:
    """Match a target against one address alias, including nested lists."""
    visited = seen if seen is not None else set()
    if alias_id in visited:
        return False
    visited.add(alias_id)

    alias = aliases.get(alias_id)
    if alias is None:
        return False
    if _ip_in_alias(alias, ip, host):
        return True

    nested_values: list[Any] = []
    if alias.value is not None:
        nested_values.append(alias.value)
    if alias.values:
        nested_values.extend(alias.values)
    return any(
        isinstance(value, str) and value in aliases and _alias_matches_target(value, aliases, ip, host, visited)
        for value in nested_values
    )


def _alias_nonmatch_is_certain(
    alias_id: str,
    aliases: dict[str, S.Alias],
    seen: set[str] | None = None,
) -> bool:
    """Whether all alias values can be decided without unavailable NGFW data."""
    visited = seen if seen is not None else set()
    if alias_id in visited:
        return False
    visited.add(alias_id)

    alias = aliases.get(alias_id)
    if alias is None:
        return False
    alias_type = (alias.type or "").lower()
    if "country" in alias_type or "iplist" in alias_type:
        return False

    checks: list[bool] = []
    if alias.start is not None or alias.end is not None:
        try:
            ipaddress.ip_address(str(alias.start))
            ipaddress.ip_address(str(alias.end))
            checks.append(True)
        except ValueError:
            checks.append(False)

    values: list[Any] = []
    if alias.value is not None:
        values.append(alias.value)
    if alias.values:
        values.extend(alias.values)
    for value in values:
        if not isinstance(value, str):
            checks.append(False)
        elif value in aliases:
            checks.append(_alias_nonmatch_is_certain(value, aliases, set(visited)))
        elif _is_raw_ip_spec(value) or ("domain" in alias_type or not alias_type) and _looks_like_domain(value):
            checks.append(True)
        else:
            checks.append(False)
    return bool(checks) and all(checks)


def _alias_match_state(
    alias_id: str,
    aliases: dict[str, S.Alias],
    ip: str | None,
    host: str,
) -> bool | None:
    """Tri-state alias matching; ``None`` preserves a possible earlier rule."""
    if alias_id not in aliases:
        return None
    if _alias_matches_target(alias_id, aliases, ip, host):
        return True
    if ip is None and _alias_may_match_ip(alias_id, aliases):
        return None
    return False if _alias_nonmatch_is_certain(alias_id, aliases) else None


def _source_match_state(
    block: S.SourceDest,
    user_tokens: set[str],
    source_ip: str | None,
    aliases: dict[str, S.Alias],
) -> bool | None:
    """Tri-state match for one source block; a missing required IP is unknown."""
    references = list(block.addresses)
    if not references:
        return True
    matched = False
    ip_dependent = False
    unresolved_reference = False
    for reference in references:
        if reference == "any" or reference in user_tokens:
            matched = True
            break
        if reference.startswith(("user.", "group.")):
            continue
        if source_ip is None:
            ip_dependent = True
            continue
        match_state = _alias_match_state(reference, aliases, source_ip, source_ip) if reference in aliases else None
        if match_state is True or _raw_ip_matches(reference, source_ip):
            matched = True
            break
        if match_state is None and (reference in aliases or not _is_raw_ip_spec(reference)):
            unresolved_reference = True
    if not matched and ip_dependent:
        return None
    if not matched and unresolved_reference:
        return None
    return not matched if block.addresses_negate else matched


def _source_matches(
    block: S.SourceDest,
    user_tokens: set[str],
    source_ip: str | None,
    aliases: dict[str, S.Alias],
) -> bool:
    return _source_match_state(block, user_tokens, source_ip, aliases) is True


def _alias_may_match_ip(alias_id: str, aliases: dict[str, S.Alias], seen: set[str] | None = None) -> bool:
    """Return whether an alias needs a destination IP before it can be ruled out."""
    visited = seen if seen is not None else set()
    if alias_id in visited:
        return False
    visited.add(alias_id)

    alias = aliases.get(alias_id)
    if alias is None:
        return False
    if alias.start is not None or alias.end is not None:
        return True

    alias_type = (alias.type or "").lower()
    values: list[Any] = []
    if alias.value is not None:
        values.append(alias.value)
    if alias.values:
        values.extend(alias.values)
    for value in values:
        if not isinstance(value, str):
            continue
        if value in aliases and _alias_may_match_ip(value, aliases, visited):
            return True
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            continue

    if "domain" in alias_type:
        return False
    return not (
        not alias_type and values and all(_looks_like_domain(str(value)) for value in values if isinstance(value, str))
    )


def _dest_match_state(
    block: S.SourceDest,
    aliases: dict[str, S.Alias],
    ip: str | None,
    host: str,
) -> bool | None:
    """Tri-state destination match; ``None`` means unresolved context matters."""
    references = list(block.addresses)
    if not references:
        return True
    matched = False
    ip_dependent = False
    unresolved_reference = False
    for reference in references:
        if reference == "any":
            matched = True
            break
        match_state = _alias_match_state(reference, aliases, ip, host) if reference in aliases else None
        if match_state is True or (reference not in aliases and _raw_ip_matches(reference, ip)):
            matched = True
            break
        if reference not in aliases:
            if _is_raw_ip_spec(reference) and ip is None:
                ip_dependent = True
            elif not _is_raw_ip_spec(reference):
                unresolved_reference = True
        elif match_state is None:
            ip_dependent = True
    if not matched and ip_dependent:
        return None
    if not matched and unresolved_reference:
        return None
    return not matched if block.addresses_negate else matched


def _sources_block_matches(
    rule: S.FirewallRule,
    user_tokens: set[str],
    source_ip: str | None,
    aliases: dict[str, S.Alias],
) -> bool:
    return not rule.sources or all(_source_matches(block, user_tokens, source_ip, aliases) for block in rule.sources)


def _sources_block_match_state(
    rule: S.FirewallRule,
    user_tokens: set[str],
    source_ip: str | None,
    aliases: dict[str, S.Alias],
) -> bool | None:
    if not rule.sources:
        return True
    states = [_source_match_state(block, user_tokens, source_ip, aliases) for block in rule.sources]
    if False in states:
        return False
    return None if None in states else True


def _dests_block_match_state(
    rule: S.FirewallRule, aliases: dict[str, S.Alias], ip: str | None, host: str
) -> bool | None:
    if not rule.destinations:
        return True
    states = [_dest_match_state(block, aliases, ip, host) for block in rule.destinations]
    if False in states:
        return False
    return None if None in states else True


def _unknown_object_reason(*, address: str | None) -> str:
    return "fw_destination_unknown" if address is None else "fw_object_unknown"


def _cf_rule_applies_to_user(rule: S.ContentFilterRule, user_tokens: set[str]) -> bool:
    if not rule.aliases:
        return True
    aliases = {str(alias).strip() for alias in rule.aliases if str(alias).strip()}
    return "any" in {alias.lower() for alias in aliases} or bool(aliases & user_tokens)


def rules_applicable_to_user(snapshot: RulesSnapshot, user: S.NgfwUser) -> dict[str, list[Any]]:
    """Return the per-user rule slice used by the read-only rules export."""
    tokens = _user_tokens(user)
    return {
        "fw_forward": [
            rule for rule in snapshot.fw_forward if _sources_block_matches(rule, tokens, None, snapshot.aliases)
        ],
        "fw_input": [
            rule for rule in snapshot.fw_input if _sources_block_matches(rule, tokens, None, snapshot.aliases)
        ],
        "fw_dnat": [rule for rule in snapshot.fw_dnat if _sources_block_matches(rule, tokens, None, snapshot.aliases)],
        "fw_snat": [rule for rule in snapshot.fw_snat if _sources_block_matches(rule, tokens, None, snapshot.aliases)],
        "cf_rules": [rule for rule in snapshot.cf_rules if _cf_rule_applies_to_user(rule, tokens)],
        "ips_bypass": [entry for entry in snapshot.ips_bypass if set(entry.aliases) & tokens],
    }


def _raw_ip_matches(spec: str | None, ip: str | None) -> bool:
    if not spec:
        return True
    if ip is None:
        return False
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False
    value = spec.strip()
    try:
        if "-" in value:
            start, end = (part.strip() for part in value.split("-", 1))
            return ipaddress.ip_address(start) <= target <= ipaddress.ip_address(end)
        if "/" in value:
            return target in ipaddress.ip_network(value, strict=False)
        return target == ipaddress.ip_address(value)
    except ValueError:
        return False


def _is_raw_ip_spec(spec: str) -> bool:
    value = spec.strip()
    try:
        if "-" in value:
            start, end = (part.strip() for part in value.split("-", 1))
            ipaddress.ip_address(start)
            ipaddress.ip_address(end)
        elif "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _single_nat_ip(value: str | None, aliases: dict[str, S.Alias]) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    alias = aliases.get(candidate)
    if alias is not None and isinstance(alias.value, str):
        candidate = alias.value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _is_ngfw_address(addresses: Iterable[str], ip: str | None) -> bool:
    if ip is None:
        return False
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for value in addresses:
        try:
            if ipaddress.ip_interface(value).ip == target:
                return True
        except ValueError:
            continue
    return False


def _bypass_matches(
    bypass: list[S.IpsBypass],
    aliases: dict[str, S.Alias],
    user_tokens: set[str],
    ip: str | None,
    host: str,
) -> S.IpsBypass | None:
    for entry in bypass:
        if not entry.enabled:
            continue
        for alias_id in entry.aliases:
            if alias_id in user_tokens:
                return entry
            alias = aliases.get(alias_id)
            if alias and _ip_in_alias(alias, ip, host):
                return entry
    return None


def _ip_equal(spec: str | None, ip: str | None) -> bool:
    if not spec or not ip:
        return False
    try:
        return ipaddress.ip_address(spec.strip()) == ipaddress.ip_address(ip)
    except ValueError:
        return spec.strip() == ip

"""Local, read-only trace engine.

Given a target URL (+ optional NGFW user) and a rules snapshot, it computes the
verdict of each processing stage in the NGFW web-traffic order
(docs/NGFW_API_NOTES.md) and returns the exact contract shape of
``POST /api/trace`` (docs/API_CONTRACT.md).

Design decision (analyst open question #2 / #3): STUCK evaluates firewall rules
LOCALLY and never calls the native ``checks_*`` API, because those endpoints
create/mutate configuration on the NGFW. Local evaluation is read-only and safe.
Rationale and uncertainty rules are recorded in docs/ARCHITECTURE.md.

Offline limits: antivirus and IPS signature matching on real payload cannot be
reproduced without live traffic, so those stages report module state
(pass/skip/bypass) and never a content-level block.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from ..config import get_settings
from ..ngfw import endpoints as ep
from ..ngfw import schemas as S
from ..ngfw.client import NgfwClient
from .binding_pool import RulesSnapshot

# Fixed stage order: packet pre-filtering and NAT are explicit, read-only stages.
# hw_filter is FIRST: hardware filtering drops packets at the NIC, before any
# software stage (docs/NGFW_API_NOTES.md).
_STAGE_ORDER: list[str] = [
    "hw_filter",
    "pre_filter",
    "rate_limit",
    "dns",
    "dnat",
    "content_filter",
    "antivirus",
    "firewall",
    "app_control",
    "ips",
    "snat",
    "destination",
]


# --- URL / DNS helpers -------------------------------------------------------


def normalize_target(raw_url: str, default_port: int) -> tuple[str, str, int]:
    """Return (normalized_url, host, dst_port_from_url_or_default).

    Accepts a bare domain or a full URL. dst_port is taken from an explicit
    ``:port`` in the URL if present, else the caller's default.
    """
    text = (raw_url or "").strip()
    if not text:
        raise ValueError("empty url")

    parsed = urlsplit(text if "://" in text else f"//{text}", scheme="")
    host = parsed.hostname
    if not host:
        # Fallback: strip path manually.
        host = text.split("/")[0].split(":")[0]
    if not host:
        raise ValueError("could not extract host")

    port = parsed.port or default_port
    scheme = parsed.scheme or ("https" if port == 443 else "http")
    normalized = f"{scheme}://{host}"
    if parsed.port:
        normalized += f":{parsed.port}"
    if parsed.path and parsed.path != "/":
        normalized += parsed.path
    return normalized, host.lower(), int(port)


async def resolve_ip(host: str) -> Optional[str]:
    """Best-effort DNS resolution of host -> first IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return host  # already an IP literal
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror, OSError:
        return None
    for info in infos:
        addr = info[4][0]
        if addr:
            return addr
    return None


# --- Alias / matching helpers ------------------------------------------------


def _user_tokens(user: Optional[S.NgfwUser]) -> set[str]:
    """Identity alias tokens the user matches in rule source/aliases lists."""
    if user is None:
        return set()
    tokens: set[str] = {"any"}
    uid = str(user.id)
    tokens.add(uid)
    if not uid.startswith("user."):
        tokens.add(f"user.id.{uid}")
    if user.parent_id:
        pid = str(user.parent_id)
        tokens.add(pid)
        if not pid.startswith("group."):
            tokens.add(f"group.id.{pid}")
    return tokens


def _ip_in_alias(alias: S.Alias, ip: Optional[str], host: str) -> bool:
    """True if the destination ip/host matches an address-like alias."""
    t = (alias.type or "").lower()
    values: list[Any] = []
    if alias.value is not None:
        values.append(alias.value)
    if alias.values:
        values.extend(alias.values)

    # Domain alias: match by host.
    if "domain" in t or (isinstance(alias.value, str) and _looks_like_domain(alias.value)):
        for v in values:
            if isinstance(v, str) and _host_matches_domain(host, v):
                return True

    if ip is None:
        return False
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # Range alias.
    if alias.start is not None and alias.end is not None:
        try:
            if ipaddress.ip_address(str(alias.start)) <= target <= ipaddress.ip_address(str(alias.end)):
                return True
        except ValueError:
            pass

    for v in values:
        if not isinstance(v, str):
            continue
        try:
            if "/" in v:
                if target in ipaddress.ip_network(v, strict=False):
                    return True
            elif ipaddress.ip_address(v) == target:
                return True
        except ValueError:
            continue
    return False


def _looks_like_domain(v: str) -> bool:
    if any(c.isalpha() for c in v) and "/" not in v:
        try:
            ipaddress.ip_address(v)
            return False
        except ValueError:
            return True
    return False


def _host_matches_domain(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().lstrip("*.").rstrip(".")
    return host == domain or host.endswith("." + domain)


def _alias_matches_target(
    alias_id: str,
    aliases: dict[str, S.Alias],
    ip: Optional[str],
    host: str,
    seen: set[str] | None = None,
) -> bool:
    """Match a target against one address alias, including nested alias lists."""

    visited = seen if seen is not None else set()
    if alias_id in visited:
        return False
    visited.add(alias_id)

    alias = aliases.get(alias_id)
    if alias is None:
        return False
    if _ip_in_alias(alias, ip, host):
        return True

    nested: list[Any] = []
    if alias.value is not None:
        nested.append(alias.value)
    if alias.values:
        nested.extend(alias.values)
    return any(
        isinstance(value, str) and value in aliases and _alias_matches_target(value, aliases, ip, host, visited)
        for value in nested
    )


def _source_match_state(
    block: S.SourceDest,
    user_tokens: set[str],
    source_ip: Optional[str],
    aliases: dict[str, S.Alias],
) -> Optional[bool]:
    """Whether the source side (a single addresses list) matches the subject.

    ``None`` means an address condition cannot be decided without a source IP.
    User/group identity conditions remain decidable without one.
    """
    ids = list(block.addresses)
    if not ids:
        return True  # empty = any
    matched = False
    ip_dependent = False
    for a in ids:
        if a == "any":
            matched = True
            break
        if a in user_tokens:
            matched = True
            break
        # A different explicit user/group is a known non-match. Everything
        # else may be an address object (or a raw address) and is unknown when
        # the selected user has no source IP.
        if a.startswith(("user.", "group.")):
            continue
        if source_ip is None:
            ip_dependent = True
            continue
        if _alias_matches_target(a, aliases, source_ip, source_ip) or _raw_ip_matches(a, source_ip):
            matched = True
            break
    if not matched and ip_dependent:
        return None
    return not matched if block.addresses_negate else matched


def _source_matches(
    block: S.SourceDest,
    user_tokens: set[str],
    source_ip: Optional[str],
    aliases: dict[str, S.Alias],
) -> bool:
    """Compatibility wrapper for contexts that require a definite match."""

    return _source_match_state(block, user_tokens, source_ip, aliases) is True


def _dest_matches(block: S.SourceDest, aliases: dict[str, S.Alias], ip: Optional[str], host: str) -> bool:
    ids = list(block.addresses)
    if not ids:
        return True
    matched = False
    for a in ids:
        if a == "any":
            matched = True
            break
        alias = aliases.get(a)
        if alias and _ip_in_alias(alias, ip, host):
            matched = True
            break
    return not matched if block.addresses_negate else matched


def _sources_block_matches(
    rule: S.FirewallRule,
    user_tokens: set[str],
    source_ip: Optional[str],
    aliases: dict[str, S.Alias],
) -> bool:
    if not rule.sources:
        return True
    # Up to 2 lists, combined with AND.
    return all(_source_matches(sd, user_tokens, source_ip, aliases) for sd in rule.sources)


def _sources_block_match_state(
    rule: S.FirewallRule,
    user_tokens: set[str],
    source_ip: Optional[str],
    aliases: dict[str, S.Alias],
) -> Optional[bool]:
    """Tri-state match for the AND-combined source blocks of a rule."""

    if not rule.sources:
        return True
    states = [_source_match_state(sd, user_tokens, source_ip, aliases) for sd in rule.sources]
    if False in states:
        return False
    if None in states:
        return None
    return True


def _dests_block_matches(rule: S.FirewallRule, aliases, ip, host) -> bool:
    if not rule.destinations:
        return True
    return all(_dest_matches(sd, aliases, ip, host) for sd in rule.destinations)


def _cf_rule_applies_to_user(rule: S.ContentFilterRule, user_tokens: set[str]) -> bool:
    """Same "Применяется для" logic as _evaluate_content_filter, ignoring URL.

    NGFW serializes an unconditional source both as an empty list and as the
    special alias ``any``. Otherwise the rule must reference the user (or one
    of their groups).
    """
    if not rule.aliases:
        return True
    aliases = {str(alias).strip() for alias in rule.aliases if str(alias).strip()}
    return "any" in {alias.lower() for alias in aliases} or bool(aliases & user_tokens)


def rules_applicable_to_user(snap: RulesSnapshot, user: S.NgfwUser) -> dict[str, list[Any]]:
    """Slice of rules applicable to one NGFW end-user (for GET /api/rules/export).

    Reuses the trace engine's source/alias matching so the export slice is
    consistent with what POST /api/trace evaluates. The URL/destination
    dimension is not applied here — this is a per-user rule slice, not a trace.
    Both enabled and disabled applicable rules are kept (the ``enabled`` flag is
    preserved in each rule) so the slice is faithful for inspection and fixtures.
    """
    tokens = _user_tokens(user)
    return {
        "fw_forward": [r for r in snap.fw_forward if _sources_block_matches(r, tokens, None, snap.aliases)],
        "fw_input": [r for r in snap.fw_input if _sources_block_matches(r, tokens, None, snap.aliases)],
        "fw_dnat": [r for r in snap.fw_dnat if _sources_block_matches(r, tokens, None, snap.aliases)],
        "fw_snat": [r for r in snap.fw_snat if _sources_block_matches(r, tokens, None, snap.aliases)],
        "cf_rules": [r for r in snap.cf_rules if _cf_rule_applies_to_user(r, tokens)],
        "ips_bypass": [b for b in snap.ips_bypass if set(b.aliases) & tokens],
    }


def _protocol_matches(rule_proto: str, requested: str) -> bool:
    rp = (rule_proto or "any").lower()
    if rp in ("any", "protocol.any", ""):
        return True
    if rp in {"6", "tcp"}:
        return requested.lower() == "tcp"
    if rp in {"17", "udp"}:
        return requested.lower() == "udp"
    return rp.endswith(requested.lower())


def _ports_match(port_ids: Iterable[str], aliases: dict[str, S.Alias], dst_port: int) -> bool:
    ids = list(port_ids)
    if not ids:
        return True
    matched_any_resolvable = False
    for a in ids:
        if a == "any":
            return True
        alias = aliases.get(a)
        if not alias:
            continue
        matched_any_resolvable = True
        # single port
        if alias.value is not None:
            try:
                if int(alias.value) == dst_port:
                    return True
            except ValueError, TypeError:
                pass
        # port range
        if alias.start is not None and alias.end is not None:
            try:
                if int(alias.start) <= dst_port <= int(alias.end):
                    return True
            except ValueError, TypeError:
                pass
        # port list
        for v in alias.values or []:
            try:
                if int(v) == dst_port:
                    return True
            except ValueError, TypeError:
                continue
    # If none of the port aliases were resolvable, be lenient (don't exclude).
    return not matched_any_resolvable


def _raw_ip_matches(spec: Optional[str], ip: Optional[str]) -> bool:
    """Match an IP against a primitive CSV/NAT address or range."""

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


def _raw_port_matches(spec: Optional[str], port: int) -> bool:
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


def _single_nat_ip(value: Optional[str], aliases: dict[str, S.Alias]) -> Optional[str]:
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


def _single_nat_port(value: Optional[str], aliases: dict[str, S.Alias]) -> Optional[int]:
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


def _is_ngfw_address(addresses: Iterable[str], ip: Optional[str]) -> bool:
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


def _has_specific_values(values: Iterable[str]) -> bool:
    """Whether an API condition is narrower than the unconditional `any`."""

    normalized = {str(value).strip().lower() for value in values if str(value).strip()}
    return bool(normalized - {"any"})


def _bypass_matches(
    bypass: list[S.IpsBypass],
    aliases: dict[str, S.Alias],
    user_tokens: set[str],
    ip: Optional[str],
    host: str,
) -> Optional[S.IpsBypass]:
    for entry in bypass:
        if not entry.enabled:
            continue
        for a in entry.aliases:
            if a in user_tokens:
                return entry
            alias = aliases.get(a)
            if alias and _ip_in_alias(alias, ip, host):
                return entry
    return None


def _ip_equal(spec: Optional[str], ip: Optional[str]) -> bool:
    """Exact single-address comparison (hardware rules carry no masks)."""
    if not spec or not ip:
        return False
    try:
        return ipaddress.ip_address(spec.strip()) == ipaddress.ip_address(ip)
    except ValueError:
        return spec.strip() == ip


def _evaluate_hw_filter(snap: RulesSnapshot, source_ip: Optional[str], resolved_ip: Optional[str]) -> dict[str, Any]:
    """Hardware (NIC-level) filtering — the very first thing a packet meets.

    One mode is active at a time (``/firewall/hw_settings``); only that mode's
    rule list applies, and a matching enabled rule DROPS the packet in the
    network card. IP rules are exact addresses without masks. Invariant #7:
    missing context (no source IP, unresolved destination, unknowable MAC)
    yields ``unknown`` — never a skipped possible block.
    """
    if snap.hw_settings is None:
        # The NGFW does not expose hardware filtering (pre-v22) — skip, honestly.
        return _stage("hw_filter", "skip", {"module_enabled": False, "reason_key": "hw_not_supported"})

    # ``mode`` is a validated Literal: an unknown value never reaches here (it
    # fails the snapshot load as api_changed — no fail-open pass is possible).
    mode = snap.hw_settings.mode
    rules_by_mode: dict[str, list[Any]] = {
        "mac": snap.hw_rules_mac,
        "src-ip": snap.hw_rules_src_ip,
        "dst-ip": snap.hw_rules_dst_ip,
        "src-and-dst-ip": snap.hw_rules_src_dst_ip,
    }
    enabled = [r for r in rules_by_mode[mode] if r.enabled]
    detail: dict[str, Any] = {"module_enabled": True, "hw_mode": mode}

    if not enabled:
        detail["reason_key"] = "hw_no_matching_rule"
        return _stage("hw_filter", "pass", detail)

    if mode == "mac":
        # The trace has no MAC context; an enabled MAC rule may match anything.
        detail["reason_key"] = "hw_mac_unknown"
        return _stage("hw_filter", "unknown", detail)

    needs_source = mode in ("src-ip", "src-and-dst-ip")
    needs_destination = mode in ("dst-ip", "src-and-dst-ip")
    if needs_source and source_ip is None:
        detail["reason_key"] = "hw_source_ip_unknown"
        return _stage("hw_filter", "unknown", detail)
    if needs_destination and resolved_ip is None:
        detail["reason_key"] = "hw_destination_unknown"
        return _stage("hw_filter", "unknown", detail)

    for rule in enabled:
        source_ok = _ip_equal(rule.source_ip, source_ip) if needs_source else True
        destination_ok = _ip_equal(rule.destination_ip, resolved_ip) if needs_destination else True
        if source_ok and destination_ok:
            detail.update(
                {
                    "rule_id": str(rule.id),
                    "rule_name": rule.comment or None,
                    "action": "drop",
                    "reason_key": "hw_rule_blocked",
                }
            )
            return _stage("hw_filter", "block", detail)

    detail["reason_key"] = "hw_no_matching_rule"
    return _stage("hw_filter", "pass", detail)


def _evaluate_rate_limit(
    snap: RulesSnapshot,
    user_tokens: set[str],
    ip: Optional[str],
    host: str,
) -> dict[str, Any]:
    if not snap.shaper_state.enabled:
        return _stage(
            "rate_limit",
            "skip",
            {"module_enabled": False, "reason_key": "rate_limit_disabled"},
        )

    for rule in snap.shaper_rules:
        if not rule.enabled:
            continue
        rule_aliases = [str(alias).strip() for alias in rule.aliases if str(alias).strip()]
        matches = not rule_aliases
        for alias_id in rule_aliases:
            if alias_id.lower() == "any" or alias_id in user_tokens:
                matches = True
                break
            if _alias_matches_target(alias_id, snap.aliases, ip, host):
                matches = True
                break
        if not matches:
            continue

        speed = float(rule.speed_value)
        speed_value: int | float = int(speed) if speed.is_integer() else speed
        return _stage(
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

    return _stage(
        "rate_limit",
        "pass",
        {"module_enabled": True, "reason_key": "rate_limit_no_matching_rule"},
    )


def _evaluate_dns(host: str, resolved_ip: Optional[str]) -> dict[str, Any]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return _stage("dns", "skip", {"reason_key": "dns_not_required"})

    if resolved_ip is None:
        return _stage("dns", "unknown", {"reason_key": "dns_lookup_failed"})

    # NGFW exposes DNS service state/configuration, but no read-only endpoint
    # that answers whether a selected user's future query would be permitted.
    # Local resolution is still useful for later address-rule matching, but it
    # must not be presented as proof that NGFW DNS policy passed.
    return _stage(
        "dns",
        "resolved",
        {"reason_key": "dns_policy_unknown", "resolved_ip": resolved_ip},
    )


# --- Category name resolution ------------------------------------------------


def build_category_names(cf_categories: Any) -> dict[str, str]:
    """Best-effort id -> human title map from the /content-filter/categories payload."""
    names: dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            cid = node.get("id")
            title = node.get("title") or node.get("name")
            if isinstance(cid, (str, int)) and isinstance(title, str):
                names[str(cid)] = title
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(cf_categories)
    return names


# --- Stage construction ------------------------------------------------------


def _stage(key: str, status: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    st: dict[str, Any] = {
        "key": key,
        "order": _STAGE_ORDER.index(key) + 1,
        "title_key": f"stage.{key}",
        "status": status,
    }
    if detail:
        st["detail"] = {k: v for k, v in detail.items() if v is not None}
    return st


def _evaluate_pre_filter(
    snap: RulesSnapshot,
    source_ip: Optional[str],
    destination_ip: Optional[str],
    protocol: str,
    dst_port: int,
) -> dict[str, Any]:
    if not snap.fw_state.enabled:
        return _stage(
            "pre_filter",
            "skip",
            {"module_enabled": False, "reason_key": "pre_filter_disabled"},
        )
    for rule in snap.fw_pre_filter:
        if not rule.enabled or not _protocol_matches(rule.protocol, protocol):
            continue
        if not _raw_ip_matches(rule.destination_address, destination_ip):
            continue
        if not _raw_port_matches(rule.destination_port, dst_port):
            continue
        if rule.source_address and source_ip is None:
            return _stage(
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
            return _stage(
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
        return _stage(
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
    return _stage(
        "pre_filter",
        "pass",
        {"module_enabled": True, "reason_key": "pre_filter_no_matching_rule"},
    )


def _nat_rule_match_state(
    rule: S.FirewallRule,
    snap: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> Optional[bool]:
    if (
        not rule.enabled
        or not _protocol_matches(rule.protocol, protocol)
        or not _dests_block_matches(rule, snap.aliases, destination_ip, host)
        or not _ports_match(rule.destination_ports, snap.aliases, dst_port)
    ):
        return False
    return _sources_block_match_state(rule, user_tokens, source_ip, snap.aliases)


def _nat_conditions_unknown(rule: S.FirewallRule, *, dnat: bool) -> bool:
    return (
        _has_specific_values(rule.source_ports)
        or _has_specific_values(rule.timetable)
        or (dnat and rule.incoming_interface not in ("", "any"))
        or (not dnat and rule.outgoing_interface not in ("", "any"))
    )


def _evaluate_dnat(
    snap: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> tuple[dict[str, Any], Optional[str], int]:
    if not snap.fw_state.enabled:
        return (
            _stage("dnat", "skip", {"module_enabled": False, "reason_key": "dnat_disabled"}),
            destination_ip,
            dst_port,
        )
    for rule in snap.fw_dnat:
        match_state = _nat_rule_match_state(
            rule, snap, user_tokens, source_ip, destination_ip, host, protocol, dst_port
        )
        if match_state is False:
            continue
        detail = {
            "rule_id": str(rule.id),
            "rule_name": rule.comment or None,
            "action": (rule.action or "accept").lower(),
            "module_enabled": True,
        }
        if match_state is None:
            detail["reason_key"] = "source_ip_unknown"
            return _stage("dnat", "unknown", detail), destination_ip, dst_port
        if _nat_conditions_unknown(rule, dnat=True):
            detail["reason_key"] = "dnat_conditions_unknown"
            return _stage("dnat", "unknown", detail), destination_ip, dst_port
        if detail["action"] == "accept":
            detail["reason_key"] = "dnat_accept"
            return _stage("dnat", "pass", detail), destination_ip, dst_port
        if detail["action"] != "dnat":
            detail["reason_key"] = "dnat_action_unknown"
            return _stage("dnat", "unknown", detail), destination_ip, dst_port

        changed_ip = (
            _single_nat_ip(rule.change_destination_address, snap.aliases)
            if rule.change_destination_address
            else destination_ip
        )
        changed_port = (
            _single_nat_port(rule.change_destination_port, snap.aliases) if rule.change_destination_port else dst_port
        )
        if changed_ip is None or changed_port is None:
            detail["reason_key"] = "dnat_transform_unknown"
            return _stage("dnat", "unknown", detail), destination_ip, dst_port
        detail.update(
            {
                "translated_destination_ip": changed_ip,
                "translated_destination_port": changed_port,
                "reason_key": "dnat_applied",
            }
        )
        return _stage("dnat", "applied", detail), changed_ip, changed_port
    return (
        _stage("dnat", "pass", {"module_enabled": True, "reason_key": "dnat_no_matching_rule"}),
        destination_ip,
        dst_port,
    )


def _evaluate_snat(
    snap: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> dict[str, Any]:
    if not snap.fw_state.enabled:
        return _stage("snat", "skip", {"module_enabled": False, "reason_key": "snat_disabled"})
    for rule in snap.fw_snat:
        match_state = _nat_rule_match_state(
            rule, snap, user_tokens, source_ip, destination_ip, host, protocol, dst_port
        )
        if match_state is False:
            continue
        action = (rule.action or "accept").lower()
        detail = {
            "rule_id": str(rule.id),
            "rule_name": rule.comment or None,
            "action": action,
            "module_enabled": True,
        }
        if match_state is None:
            detail["reason_key"] = "source_ip_unknown"
            return _stage("snat", "unknown", detail)
        if _nat_conditions_unknown(rule, dnat=False):
            detail["reason_key"] = "snat_conditions_unknown"
            return _stage("snat", "unknown", detail)
        if action == "accept":
            detail["reason_key"] = "snat_accept"
            return _stage("snat", "pass", detail)
        if action != "snat":
            detail["reason_key"] = "snat_action_unknown"
            return _stage("snat", "unknown", detail)
        changed_ip = _single_nat_ip(rule.change_source_address, snap.aliases)
        if changed_ip is None:
            detail["reason_key"] = "snat_transform_unknown"
            return _stage("snat", "unknown", detail)
        detail.update(
            {
                "translated_source_ip": changed_ip,
                "reason_key": "snat_applied",
            }
        )
        return _stage("snat", "applied", detail)
    if snap.fw_settings.automatic_snat_enabled:
        return _stage(
            "snat",
            "active",
            {"module_enabled": True, "reason_key": "snat_automatic_active"},
        )
    return _stage(
        "snat",
        "pass",
        {"module_enabled": True, "reason_key": "snat_no_matching_rule"},
    )


def _evaluate_content_filter(
    snap: RulesSnapshot,
    url_categories: list[str],
    user_tokens: set[str],
    cat_names: dict[str, str],
) -> dict[str, Any]:
    if not snap.cf_state.enabled:
        return _stage("content_filter", "skip", {"module_enabled": False, "reason_key": "cf_disabled"})
    cat_set = set(url_categories)
    for rule in snap.cf_rules:
        if not rule.enabled:
            continue
        # "Применяется для": empty = all; else must intersect the subject.
        if not _cf_rule_applies_to_user(rule, user_tokens):
            continue
        # http method (web trace assumes GET)
        if rule.http_methods and "GET" not in {m.upper() for m in rule.http_methods}:
            continue
        # category match: empty categories = applies to any URL
        matched_cat = None
        if rule.categories:
            inter = set(rule.categories) & cat_set
            if not inter:
                continue
            matched_cat = next(iter(inter))
        # The request contains only a URL, not an observed HTTP response body
        # or a fully modelled NGFW schedule. This rule may be the first one
        # that applies, so continuing to a later rule would be incorrect.
        if rule.content_types or _has_specific_values(rule.timetable):
            return _stage(
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
            "matched_category": cat_names.get(matched_cat, matched_cat) if matched_cat else None,
            "module_enabled": True,
        }
        if access in ("allow", "bump"):
            detail["reason_key"] = "cf_allowed"
            return _stage("content_filter", "pass", detail)
        if access == "deny":
            detail["reason_key"] = "cf_category_blocked"
            return _stage("content_filter", "block", detail)
        if access == "redirect":
            detail["redirect_url"] = rule.redirect_url
            detail["reason_key"] = "cf_redirect"
            # A redirect diverts traffic -> treated as a block for the pipeline.
            return _stage("content_filter", "block", detail)
        # A new/unknown action must not turn into an implicit allow verdict.
        detail["reason_key"] = "cf_action_unknown"
        return _stage("content_filter", "unknown", detail)

    # No matching rule -> default allow.
    return _stage("content_filter", "pass", {"module_enabled": True, "reason_key": "cf_no_matching_rule"})


def _evaluate_firewall(
    snap: RulesSnapshot,
    user_tokens: set[str],
    source_ip: Optional[str],
    ip: Optional[str],
    host: str,
    protocol: str,
    dst_port: int,
) -> tuple[dict[str, Any], Optional[S.FirewallRule]]:
    table = "input" if _is_ngfw_address(snap.ngfw_addresses, ip) else "forward"
    rules = snap.fw_input if table == "input" else snap.fw_forward
    if not snap.fw_state.enabled:
        return (
            _stage("firewall", "skip", {"module_enabled": False, "firewall_table": table, "reason_key": "fw_disabled"}),
            None,
        )
    for rule in rules:
        if not rule.enabled:
            continue
        if not _protocol_matches(rule.protocol, protocol):
            continue
        source_match_state = _sources_block_match_state(rule, user_tokens, source_ip, snap.aliases)
        if source_match_state is False:
            continue
        if not _dests_block_matches(rule, snap.aliases, ip, host):
            continue
        if not _ports_match(rule.destination_ports, snap.aliases, dst_port):
            continue
        if source_match_state is None:
            return (
                _stage(
                    "firewall",
                    "unknown",
                    {
                        "rule_id": str(rule.id),
                        "rule_name": rule.comment or None,
                        "module_enabled": True,
                        "firewall_table": table,
                        "reason_key": "source_ip_unknown",
                    },
                ),
                None,
            )
        # The trace request intentionally has no source port, interface, HIP
        # posture or complete timetable context. If this earlier rule might
        # apply, returning a later rule or an allow verdict would be unsafe.
        if (
            _has_specific_values(rule.source_ports)
            or _has_specific_values(rule.timetable)
            or rule.incoming_interface not in ("", "any")
            or rule.outgoing_interface not in ("", "any")
            or rule.hip_profiles
        ):
            return (
                _stage(
                    "firewall",
                    "unknown",
                    {
                        "rule_id": str(rule.id),
                        "rule_name": rule.comment or None,
                        "module_enabled": True,
                        "firewall_table": table,
                        "reason_key": "fw_conditions_unknown",
                    },
                ),
                None,
            )
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
            return _stage("firewall", "pass", detail), rule
        detail["reason_key"] = "fw_rule_" + action
        return _stage("firewall", "block", detail), rule

    # The NGFW default policy is not confirmed by the published API. Do not
    # present a missing rule as a successful, end-to-end traffic decision.
    return (
        _stage(
            "firewall",
            "unknown",
            {"module_enabled": True, "firewall_table": table, "reason_key": "fw_default_policy_unknown"},
        ),
        None,
    )


async def run_trace(
    snap: RulesSnapshot,
    client: NgfwClient,
    *,
    url: str,
    user: Optional[S.NgfwUser],
    protocol: str,
    dst_port_override: Optional[int],
    source_ip: Optional[str] = None,
) -> dict[str, Any]:
    """Produce the full /api/trace response body."""
    settings = get_settings()
    normalized, host, url_port = normalize_target(url, settings.STUCK_TRACE_DEFAULT_PORT)
    dst_port = dst_port_override or url_port

    resolved_ip = await resolve_ip(host)

    # Categorize the URL via NGFW (also yields a normalized URL).
    categorize = await ep.categorize(client, normalized if "://" in normalized else host)
    url_categories = categorize.all
    if categorize.normalizedUrl:
        normalized = categorize.normalizedUrl

    cat_names = build_category_names(snap.cf_categories)
    human_categories = [cat_names.get(c, c) for c in url_categories]

    user_tokens = _user_tokens(user)
    stages: list[dict[str, Any]] = []
    blocked_at: Optional[str] = None

    def add(stage: dict[str, Any]) -> None:
        nonlocal blocked_at
        stages.append(stage)
        if stage["status"] == "block" and blocked_at is None:
            blocked_at = stage["key"]

    def na(key: str) -> dict[str, Any]:
        return _stage(key, "na")

    # 0. hardware (NIC-level) filtering — before any software stage.
    add(_evaluate_hw_filter(snap, source_ip, resolved_ip))

    # 1. preliminary packet filtering — ordered blocking CSV snapshot.
    if blocked_at is None:
        add(_evaluate_pre_filter(snap, source_ip, resolved_ip, protocol, dst_port))
    else:
        add(na("pre_filter"))

    # 2. rate_limit — evaluate the ordered read-only shaper snapshot.
    if blocked_at is None:
        add(_evaluate_rate_limit(snap, user_tokens, resolved_ip, host))
    else:
        add(na("rate_limit"))

    # 3. dns — local lookup is dynamic, but NGFW has no policy dry-run API.
    if blocked_at is None:
        add(_evaluate_dns(host, resolved_ip))
    else:
        add(na("dns"))

    # 4. DNAT transforms the destination used by subsequent packet stages.
    effective_ip = resolved_ip
    effective_port = dst_port
    if blocked_at is None:
        dnat_stage, effective_ip, effective_port = _evaluate_dnat(
            snap,
            user_tokens,
            source_ip,
            resolved_ip,
            host,
            protocol,
            dst_port,
        )
        add(dnat_stage)
    else:
        add(na("dnat"))

    # 5. content_filter
    if blocked_at is None:
        add(_evaluate_content_filter(snap, url_categories, user_tokens, cat_names))
    else:
        add(na("content_filter"))

    # 6. antivirus
    if blocked_at is None:
        if snap.av_enabled:
            add(_stage("antivirus", "active", {"module_enabled": True, "reason_key": "av_active_content_unknown"}))
        else:
            add(_stage("antivirus", "skip", {"module_enabled": False, "reason_key": "av_disabled"}))
    else:
        add(na("antivirus"))

    # 7. firewall — INPUT for an NGFW interface address, otherwise FORWARD.
    matched_rule: Optional[S.FirewallRule] = None
    if blocked_at is None:
        fw_stage, matched_rule = _evaluate_firewall(
            snap,
            user_tokens,
            source_ip,
            effective_ip,
            host,
            protocol,
            effective_port,
        )
        add(fw_stage)
    else:
        add(na("firewall"))

    # 8. app_control (DPI) — only for traffic under an accepting FW rule with DPI.
    if blocked_at is None:
        if matched_rule is not None and matched_rule.dpi_enabled:
            add(_stage("app_control", "unknown", {"reason_key": "dpi_active_content_unknown"}))
        else:
            add(_stage("app_control", "skip", {"reason_key": "dpi_not_applied"}))
    else:
        add(na("app_control"))

    # 9. ips
    if blocked_at is None:
        if not snap.ips_state.enabled:
            add(_stage("ips", "skip", {"module_enabled": False, "reason_key": "ips_disabled"}))
        else:
            bypass = _bypass_matches(snap.ips_bypass, snap.aliases, user_tokens, effective_ip, host)
            if bypass is not None:
                add(
                    _stage(
                        "ips", "bypass", {"module_enabled": True, "rule_id": str(bypass.id), "reason_key": "ips_bypass"}
                    )
                )
            elif matched_rule is not None and matched_rule.ips_enabled:
                add(_stage("ips", "unknown", {"module_enabled": True, "reason_key": "ips_active_content_unknown"}))
            else:
                add(_stage("ips", "skip", {"module_enabled": True, "reason_key": "ips_not_applied"}))
    else:
        add(na("ips"))

    # 10. SNAT changes only forwarded egress traffic. INPUT terminates on NGFW.
    if blocked_at is None and _is_ngfw_address(snap.ngfw_addresses, effective_ip):
        add(_stage("snat", "skip", {"reason_key": "snat_not_applicable_input"}))
    elif blocked_at is None:
        add(
            _evaluate_snat(
                snap,
                user_tokens,
                source_ip,
                effective_ip,
                host,
                protocol,
                effective_port,
            )
        )
    else:
        add(na("snat"))

    # 11. destination. A stage with an unknown verdict means that the backend
    # cannot claim the traffic reached the destination, even when no policy
    # explicitly blocked it.
    has_unknown = any(stage["status"] == "unknown" for stage in stages)
    has_conditional = any(
        (stage["key"] == "dns" and stage["status"] == "resolved")
        or (stage["key"] == "antivirus" and stage["status"] == "active")
        or (stage["key"] == "snat" and stage["status"] == "active")
        for stage in stages
    )
    if blocked_at is None:
        if has_unknown:
            add(_stage("destination", "unknown", {"reason_key": "destination_unknown"}))
        elif has_conditional:
            add(
                _stage(
                    "destination",
                    "conditional",
                    {"reason_key": "destination_conditional"},
                )
            )
        else:
            add(_stage("destination", "pass", {"reason_key": "reached_destination"}))
    else:
        add(na("destination"))

    reached = blocked_at is None and not has_unknown and not has_conditional
    verdict = (
        "blocked"
        if blocked_at is not None
        else "unknown"
        if has_unknown
        else "conditional"
        if has_conditional
        else "allowed"
    )

    return {
        "target": {
            "input": url,
            "normalized_url": normalized,
            "host": host,
            "resolved_ip": resolved_ip,
            "source_ip": source_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "effective_destination_ip": effective_ip,
            "effective_destination_port": effective_port,
        },
        "user": ({"id": str(user.id), "name": user.name, "login": user.login} if user is not None else None),
        "categories": human_categories,
        "stages": stages,
        "summary": {
            "reached_destination": reached,
            "blocked_at": blocked_at,
            "verdict": verdict,
        },
    }

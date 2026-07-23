"""Orchestration entry point for the local, read-only traffic trace.

Matching, per-stage policy evaluation and contract construction live in the
``domain.trace`` package.  Keeping this module focused on input resolution and
pipeline orchestration makes the security-critical execution order explicit
while preserving the established public import path.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

from ..config import get_settings
from ..ngfw import endpoints as ep
from ..ngfw import schemas as S
from ..ngfw.client import NgfwClient
from .binding_pool import RulesSnapshot
from .trace.address_matching import (
    _bypass_matches,
    _is_ngfw_address,
    _user_tokens,
)
from .trace.address_matching import (
    rules_applicable_to_user as _rules_applicable_to_user,
)
from .trace.contracts import build_category_names, stage
from .trace.nat import evaluate_dnat, evaluate_snat
from .trace.network_stages import (
    evaluate_dns,
    evaluate_hw_filter,
    evaluate_pre_filter,
    evaluate_rate_limit,
    match_dns_zone,
)
from .trace.policy_stages import evaluate_content_filter, evaluate_firewall


def normalize_target(raw_url: str, default_port: int) -> tuple[str, str, int]:
    """Return the normalized URL, host and explicit-or-default destination port."""
    text = (raw_url or "").strip()
    if not text:
        raise ValueError("empty url")

    parsed = urlsplit(text if "://" in text else f"//{text}", scheme="")
    host = parsed.hostname
    if not host:
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


async def resolve_ip(host: str) -> str | None:
    """Best-effort system resolution to the first IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror, OSError:
        return None
    for info in infos:
        address = info[4][0]
        if address:
            return address
    return None


def rules_applicable_to_user(snapshot: RulesSnapshot, user: S.NgfwUser) -> dict[str, list[Any]]:
    """Return the exportable per-user rule slice from the matching component."""
    return _rules_applicable_to_user(snapshot, user)


async def run_trace(
    snapshot: RulesSnapshot,
    client: NgfwClient,
    *,
    url: str,
    user: S.NgfwUser | None,
    protocol: str,
    dst_port_override: int | None,
    source_ip: str | None = None,
) -> dict[str, Any]:
    """Produce the complete, stable ``POST /api/trace`` response body.

    The explicit calls below are the architectural source of truth for the
    fixed NGFW pipeline. A blocking stage prevents effective evaluation of all
    later stages, which are still returned as ``na`` for a stable UI contract.
    """
    settings = get_settings()
    normalized, host, url_port = normalize_target(url, settings.STUCK_TRACE_DEFAULT_PORT)
    dst_port = dst_port_override or url_port

    local_dns_zone = match_dns_zone(host, snapshot.dns_zones)
    # A system lookup can leak a private local-zone name and cannot represent
    # the NGFW answer, so skip it entirely whenever that zone is configured.
    resolved_ip = None if local_dns_zone is not None else await resolve_ip(host)

    categorize = await ep.categorize(client, normalized if "://" in normalized else host)
    url_categories = categorize.all
    if categorize.normalizedUrl:
        normalized = categorize.normalizedUrl

    category_names = build_category_names(snapshot.cf_categories)
    human_categories = [category_names.get(category, category) for category in url_categories]
    user_tokens = _user_tokens(user)
    stages: list[dict[str, Any]] = []
    blocked_at: str | None = None

    def add(result: dict[str, Any]) -> None:
        nonlocal blocked_at
        stages.append(result)
        if result["status"] == "block" and blocked_at is None:
            blocked_at = result["key"]

    def not_applicable(key: str) -> dict[str, Any]:
        return stage(key, "na")

    # 0–3: stages that operate on the original destination.
    add(evaluate_hw_filter(snapshot, source_ip, resolved_ip))
    add(
        evaluate_pre_filter(snapshot, source_ip, resolved_ip, protocol, dst_port)
        if blocked_at is None
        else not_applicable("pre_filter")
    )
    add(
        evaluate_rate_limit(snapshot, user_tokens, resolved_ip, host)
        if blocked_at is None
        else not_applicable("rate_limit")
    )
    add(evaluate_dns(snapshot, host, resolved_ip) if blocked_at is None else not_applicable("dns"))

    # 4: DNAT changes the effective target for every remaining packet stage.
    effective_ip = resolved_ip
    effective_port = dst_port
    if blocked_at is None:
        dnat_stage, effective_ip, effective_port = evaluate_dnat(
            snapshot,
            user_tokens,
            source_ip,
            resolved_ip,
            host,
            protocol,
            dst_port,
        )
        add(dnat_stage)
    else:
        add(not_applicable("dnat"))

    # 5–7: application policy and first-match firewall decision.
    add(
        evaluate_content_filter(snapshot, url_categories, user_tokens, category_names)
        if blocked_at is None
        else not_applicable("content_filter")
    )
    if blocked_at is None:
        if snapshot.av_enabled:
            add(stage("antivirus", "active", {"module_enabled": True, "reason_key": "av_active_content_unknown"}))
        else:
            add(stage("antivirus", "skip", {"module_enabled": False, "reason_key": "av_disabled"}))
    else:
        add(not_applicable("antivirus"))

    matched_rule: S.FirewallRule | None = None
    if blocked_at is None:
        firewall_stage, matched_rule = evaluate_firewall(
            snapshot,
            user_tokens,
            source_ip,
            effective_ip,
            host,
            protocol,
            effective_port,
        )
        add(firewall_stage)
    else:
        add(not_applicable("firewall"))

    # 8–10: modules that depend on the firewall result and effective target.
    if blocked_at is None:
        if matched_rule is not None and matched_rule.dpi_enabled:
            add(stage("app_control", "unknown", {"reason_key": "dpi_active_content_unknown"}))
        else:
            add(stage("app_control", "skip", {"reason_key": "dpi_not_applied"}))
    else:
        add(not_applicable("app_control"))

    if blocked_at is None:
        if not snapshot.ips_state.enabled:
            add(stage("ips", "skip", {"module_enabled": False, "reason_key": "ips_disabled"}))
        else:
            bypass = _bypass_matches(snapshot.ips_bypass, snapshot.aliases, user_tokens, effective_ip, host)
            if bypass is not None:
                add(
                    stage(
                        "ips", "bypass", {"module_enabled": True, "rule_id": str(bypass.id), "reason_key": "ips_bypass"}
                    )
                )
            elif matched_rule is not None and matched_rule.ips_enabled:
                add(stage("ips", "unknown", {"module_enabled": True, "reason_key": "ips_active_content_unknown"}))
            else:
                add(stage("ips", "skip", {"module_enabled": True, "reason_key": "ips_not_applied"}))
    else:
        add(not_applicable("ips"))

    if blocked_at is None and _is_ngfw_address(snapshot.ngfw_addresses, effective_ip):
        add(stage("snat", "skip", {"reason_key": "snat_not_applicable_input"}))
    elif blocked_at is None:
        add(evaluate_snat(snapshot, user_tokens, source_ip, effective_ip, host, protocol, effective_port))
    else:
        add(not_applicable("snat"))

    # 11: the terminal stage summarizes prior uncertainty without inventing a
    # reachability guarantee from partial offline information.
    has_unknown = any(result["status"] == "unknown" for result in stages)
    has_conditional = any(
        (result["key"] == "dns" and result["status"] == "resolved")
        or (result["key"] == "antivirus" and result["status"] == "active")
        or (result["key"] == "snat" and result["status"] == "active")
        for result in stages
    )
    if blocked_at is None:
        if has_unknown:
            add(stage("destination", "unknown", {"reason_key": "destination_unknown"}))
        elif has_conditional:
            add(stage("destination", "conditional", {"reason_key": "destination_conditional"}))
        else:
            add(stage("destination", "pass", {"reason_key": "reached_destination"}))
    else:
        add(not_applicable("destination"))

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
        "summary": {"reached_destination": reached, "blocked_at": blocked_at, "verdict": verdict},
    }

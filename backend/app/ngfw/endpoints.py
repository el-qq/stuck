"""Typed wrappers over NGFW REST endpoints used by STUCK.

Each function performs one NGFW call and parses it with the lenient schemas
(raising api_changed on shape mismatch). ``load_snapshot`` assembles the full
read-only dataset used for traces (docs/NGFW_API_NOTES.md).
"""

from __future__ import annotations

import asyncio
import csv
import io
from typing import Any

from . import schemas as S
from .client import NgfwClient


async def get_users(client: NgfwClient) -> list[S.NgfwUser]:
    data = await client.get_json("/user_backend/users")
    return S.parse_list(S.NgfwUser, data, what="users")


async def get_aliases_all(client: NgfwClient) -> dict[str, S.Alias]:
    """Return a flat ``id -> Alias`` map from ``/aliases/all``.

    NGFW may return either a flat list or an object grouping aliases by type;
    both are flattened here.
    """
    data = await client.get_json("/aliases/all")
    items: list[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                items.extend(v)
            elif isinstance(v, dict):
                items.append(v)
    else:
        raise S._api_changed("aliases", TypeError("unexpected aliases shape"))

    out: dict[str, S.Alias] = {}
    for raw in items:
        if isinstance(raw, dict) and "id" in raw:
            alias = S.parse(S.Alias, raw, what="aliases")
            out[alias.id] = alias
    return out


async def get_fw_forward(client: NgfwClient) -> list[S.FirewallRule]:
    data = await client.get_json("/firewall/rules/forward")
    return S.parse_list(S.FirewallRule, data, what="firewall_forward")


async def get_fw_input(client: NgfwClient) -> list[S.FirewallRule]:
    data = await client.get_json("/firewall/rules/input")
    return S.parse_list(S.FirewallRule, data, what="firewall_input")


async def get_fw_dnat(client: NgfwClient) -> list[S.FirewallRule]:
    data = await client.get_json("/firewall/rules/dnat")
    return S.parse_list(S.FirewallRule, data, what="firewall_dnat")


async def get_fw_snat(client: NgfwClient) -> list[S.FirewallRule]:
    data = await client.get_json("/firewall/rules/snat")
    return S.parse_list(S.FirewallRule, data, what="firewall_snat")


def _csv_value(value: str) -> str | None:
    text = value.strip()
    return None if not text or text.lower() in {"none", "null", "any"} else text


async def get_fw_pre_filter(client: NgfwClient) -> list[S.PreliminaryRule]:
    """Load preliminary drop rules through the documented CSV-only export."""

    text = await client.get_text("/firewall/rules/drop_rules/export")
    try:
        rows = csv.reader(io.StringIO(text.lstrip("\ufeff")), delimiter=";")
        next(rows, None)  # localized header; columns are stable in the API export
        parsed: list[S.PreliminaryRule] = []
        for row in rows:
            if len(row) < 11 or row[0].strip().lower() != "drop_rules":
                continue
            enabled = row[10].strip().lower() in {
                "enabled",
                "true",
                "1",
                "yes",
                "включено",
                "включен",
            }
            parsed.append(
                S.PreliminaryRule(
                    id=f"drop_rules.{len(parsed) + 1}",
                    enabled=enabled,
                    protocol=_csv_value(row[1]) or "any",
                    source_address=_csv_value(row[2]),
                    source_port=_csv_value(row[3]),
                    destination_address=_csv_value(row[4]),
                    destination_port=_csv_value(row[5]),
                    tcp_flags=row[6].strip(),
                    blocked_tcp_flags=row[7].strip(),
                    packet_length=_csv_value(row[8]),
                    comment=row[9].strip(),
                )
            )
        return parsed
    except (csv.Error, IndexError, TypeError) as exc:
        raise S._api_changed("firewall_pre_filter", exc) from exc


async def get_fw_settings(client: NgfwClient) -> S.FirewallSettings:
    data = await client.get_json("/firewall/settings")
    return S.parse(S.FirewallSettings, data, what="firewall_settings")


async def get_hw_settings(client: NgfwClient) -> S.HwFilterSettings | None:
    """Hardware filtering is OPTIONAL (absent before v22): 404 → None.

    A present endpoint is parsed strictly — an unknown ``mode`` is api_changed,
    never a silent fail-open pass.
    """
    data = await client.get_json_optional("/firewall/hw_settings")
    if data is None:
        return None
    return S.parse(S.HwFilterSettings, data, what="hw_settings")


async def _get_hw_rules(client: NgfwClient, path: str, model: type, what: str) -> list | None:
    data = await client.get_json_optional(path)
    if data is None:
        return None
    return S.parse_list(model, data, what=what)


async def get_hw_rules_mac(client: NgfwClient) -> list[S.HwRuleMac] | None:
    return await _get_hw_rules(client, "/firewall/hw_rules_mac", S.HwRuleMac, "hw_rules_mac")


async def get_hw_rules_src_ip(client: NgfwClient) -> list[S.HwRuleSrcIp] | None:
    return await _get_hw_rules(client, "/firewall/hw_rules_src_ip", S.HwRuleSrcIp, "hw_rules_src_ip")


async def get_hw_rules_dst_ip(client: NgfwClient) -> list[S.HwRuleDstIp] | None:
    return await _get_hw_rules(client, "/firewall/hw_rules_dst_ip", S.HwRuleDstIp, "hw_rules_dst_ip")


async def get_hw_rules_src_dst_ip(client: NgfwClient) -> list[S.HwRuleSrcDstIp] | None:
    return await _get_hw_rules(client, "/firewall/hw_rules_src_dst_ip", S.HwRuleSrcDstIp, "hw_rules_src_dst_ip")


async def get_ngfw_addresses(client: NgfwClient) -> list[str]:
    data = await client.get_json("/l2manager/connection_state")
    interfaces = S.parse_list(S.InterfaceState, data, what="interface_state")
    return [address for interface in interfaces for address in interface.l3]


async def get_auth_sessions(client: NgfwClient) -> list[S.AuthSession]:
    data = await client.get_json("/monitor_backend/auth_sessions")
    return S.parse_list(S.AuthSession, data, what="auth_sessions")


async def get_auth_rules(client: NgfwClient) -> list[S.AuthRule]:
    """Return configured user-to-IP/MAC bindings, including permanent ones."""

    data = await client.get_json("/auth/rules")
    return S.parse_list(S.AuthRule, data, what="auth_rules")


async def get_fw_state(client: NgfwClient) -> S.StateFlag:
    data = await client.get_json("/firewall/state")
    return S.parse(S.StateFlag, data, what="firewall_state")


async def get_cf_state(client: NgfwClient) -> S.StateFlag:
    data = await client.get_json("/content-filter/state")
    return S.parse(S.StateFlag, data, what="content_filter_state")


async def get_cf_rules(client: NgfwClient) -> list[S.ContentFilterRule]:
    data = await client.get_json("/content-filter/rules")
    return S.parse_list(S.ContentFilterRule, data, what="content_filter_rules")


async def get_cf_categories(client: NgfwClient) -> Any:
    """Raw categories payload; used only to resolve human-readable names."""
    return await client.get_json("/content-filter/categories")


async def get_shaper_state(client: NgfwClient) -> S.StateFlag:
    data = await client.get_json("/api/shaper/state")
    return S.parse(S.StateFlag, data, what="shaper_state")


async def _get_shaper_rules(client: NgfwClient, path: str, what: str) -> list[S.ShaperRule]:
    data = await client.get_json(path)
    return S.parse_list(S.ShaperRule, data, what=what)


async def get_shaper_rules_before(client: NgfwClient) -> list[S.ShaperRule]:
    return await _get_shaper_rules(client, "/api/shaper/rules/before", "shaper_rules_before")


async def get_shaper_rules(client: NgfwClient) -> list[S.ShaperRule]:
    return await _get_shaper_rules(client, "/api/shaper/rules", "shaper_rules")


async def get_shaper_rules_after(client: NgfwClient) -> list[S.ShaperRule]:
    return await _get_shaper_rules(client, "/api/shaper/rules/after", "shaper_rules_after")


async def get_ips_state(client: NgfwClient) -> S.StateFlag:
    data = await client.get_json("/ips/state")
    return S.parse(S.StateFlag, data, what="ips_state")


async def get_ips_bypass(client: NgfwClient) -> list[S.IpsBypass]:
    data = await client.get_json("/ips/bypass")
    return S.parse_list(S.IpsBypass, data, what="ips_bypass")


async def get_av_default_enabled(client: NgfwClient) -> bool:
    """Whether web antivirus is enabled with an enabled default profile.

    ``/profiles/default`` returns only ``profile_id`` — it does not contain an
    ``enabled`` flag. Module state and profile state are separate NGFW APIs.
    """
    state_data, default_data, profiles_data = await asyncio.gather(
        client.get_json("/av_backend/state"),
        client.get_json("/av_backend/profiles/default"),
        client.get_json("/av_backend/profiles"),
    )
    state = S.parse(S.StateFlag, state_data, what="antivirus_state")
    if not state.enabled:
        return False
    if not isinstance(default_data, dict) or not isinstance(profiles_data, list):
        raise S._api_changed(
            "antivirus_profile",
            TypeError("expected default profile object and profiles list"),
        )

    selected = default_data.get("profile_id")
    if not isinstance(selected, str) or not selected.strip():
        return False

    def normalize_profile_id(value: Any) -> str:
        text = str(value).strip()
        prefix = "av_profile.id."
        return text[len(prefix) :] if text.startswith(prefix) else text

    selected_id = normalize_profile_id(selected)
    for profile in profiles_data:
        if not isinstance(profile, dict) or "id" not in profile:
            continue
        if normalize_profile_id(profile["id"]) == selected_id:
            enabled = profile.get("enabled")
            if not isinstance(enabled, bool):
                raise S._api_changed(
                    "antivirus_profile",
                    TypeError("selected profile has no boolean enabled field"),
                )
            return enabled
    raise S._api_changed(
        "antivirus_profile",
        ValueError("default profile_id is absent from profiles list"),
    )


async def categorize(client: NgfwClient, url: str) -> S.Categorize:
    data = await client.get_json("/content-filter/categorize", params={"url": url})
    return S.parse(S.Categorize, data, what="categorize")


async def load_snapshot(client: NgfwClient) -> dict[str, Any]:
    """Fetch the full read-only dataset used for traces, concurrently.

    Returns a plain dict consumed by domain.binding_pool.RulesSnapshot.
    """
    tasks = [
        asyncio.create_task(coro)
        for coro in (
            get_users(client),
            get_aliases_all(client),
            get_fw_forward(client),
            get_fw_input(client),
            get_fw_dnat(client),
            get_fw_snat(client),
            get_fw_pre_filter(client),
            get_fw_settings(client),
            get_hw_settings(client),
            get_hw_rules_mac(client),
            get_hw_rules_src_ip(client),
            get_hw_rules_dst_ip(client),
            get_hw_rules_src_dst_ip(client),
            get_ngfw_addresses(client),
            get_fw_state(client),
            get_cf_state(client),
            get_cf_rules(client),
            get_cf_categories(client),
            get_shaper_state(client),
            get_shaper_rules_before(client),
            get_shaper_rules(client),
            get_shaper_rules_after(client),
            get_ips_state(client),
            get_ips_bypass(client),
            get_av_default_enabled(client),
        )
    ]
    try:
        (
            users,
            aliases,
            fw_forward,
            fw_input,
            fw_dnat,
            fw_snat,
            fw_pre_filter,
            fw_settings,
            hw_settings,
            hw_rules_mac,
            hw_rules_src_ip,
            hw_rules_dst_ip,
            hw_rules_src_dst_ip,
            ngfw_addresses,
            fw_state,
            cf_state,
            cf_rules,
            cf_categories,
            shaper_state,
            shaper_rules_before,
            shaper_rules,
            shaper_rules_after,
            ips_state,
            ips_bypass,
            av_enabled,
        ) = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return {
        "users": users,
        "aliases": aliases,
        "fw_forward": fw_forward,
        "fw_input": fw_input,
        "fw_dnat": fw_dnat,
        "fw_snat": fw_snat,
        "fw_pre_filter": fw_pre_filter,
        "fw_settings": fw_settings,
        # Hardware filtering is unavailable (None settings) when ANY of its
        # endpoints is missing — old firmware exposes none of them; a partial
        # set would make the verdict unreliable, so fail safe to "unsupported".
        "hw_settings": (
            hw_settings
            if None not in (hw_settings, hw_rules_mac, hw_rules_src_ip, hw_rules_dst_ip, hw_rules_src_dst_ip)
            else None
        ),
        "hw_rules_mac": hw_rules_mac or [],
        "hw_rules_src_ip": hw_rules_src_ip or [],
        "hw_rules_dst_ip": hw_rules_dst_ip or [],
        "hw_rules_src_dst_ip": hw_rules_src_dst_ip or [],
        "ngfw_addresses": ngfw_addresses,
        "fw_state": fw_state,
        "cf_state": cf_state,
        "cf_rules": cf_rules,
        "cf_categories": cf_categories,
        "shaper_state": shaper_state,
        # The NGFW UI renders these three sections in this order. Preserve it:
        # speed-limit processing, like the other rule engines, is first-match.
        "shaper_rules": shaper_rules_before + shaper_rules + shaper_rules_after,
        "ips_state": ips_state,
        "ips_bypass": ips_bypass,
        "av_enabled": av_enabled,
    }

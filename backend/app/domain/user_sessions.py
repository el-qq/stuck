"""Map live sessions and configured user/IP bindings to source addresses."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..ngfw import schemas as S


def _user_tokens(user_id: str) -> set[str]:
    value = str(user_id).strip()
    tokens = {value}
    if value.startswith("user.id."):
        tokens.add(value.removeprefix("user.id."))
    else:
        tokens.add(f"user.id.{value}")
    return tokens


def user_source_addresses(
    sessions: list[S.AuthSession], auth_rules: list[S.AuthRule], user_id: str
) -> list[dict[str, Any]]:
    """Return unique active or explicitly assigned IPs for one user.

    ``GET /monitor_backend/auth_sessions`` is runtime state, while
    ``GET /auth/rules`` is the source of configured IP/MAC bindings.  A
    permanent IP binding can therefore be used even when the user currently
    has no live session.
    """

    tokens = _user_tokens(user_id)
    addresses: dict[str, dict[str, Any]] = {}
    for session in sessions:
        if session.user_object_id not in tokens:
            continue
        if session.blocked_flags != 0 or session.state_flags & 1:
            continue
        try:
            source_ip = str(ipaddress.ip_interface(session.subnet).ip)
        except ValueError:
            continue
        addresses.setdefault(
            source_ip,
            {
                "ip": source_ip,
                "subnet": session.subnet,
                "external_ip": session.external_ip,
                "auth_module": session.auth_module,
                "node_name": session.node_name,
                "active": True,
                "assigned": False,
            },
        )

    for rule in auth_rules:
        if rule.user_object_id not in tokens or not rule.enabled or not rule.ip:
            continue
        try:
            source_ip = str(ipaddress.ip_interface(rule.ip).ip)
        except ValueError:
            continue
        current = addresses.get(source_ip)
        if current is not None:
            current["assigned"] = True
            continue
        addresses[source_ip] = {
            "ip": source_ip,
            "subnet": rule.ip,
            "external_ip": None,
            "auth_module": "ip_permanent" if rule.always_logged else "ip",
            "node_name": None,
            "active": False,
            "assigned": True,
        }
    return sorted(addresses.values(), key=lambda item: ipaddress.ip_address(item["ip"]))

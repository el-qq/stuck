"""Resolve the two access-compare side subjects with per-side diagnostics.

Each side is the same subject model as a single trace (``user_id?`` +
``source_ip?``). Resolution mirrors ``api/trace.py`` (unknown user, invalid IP,
IP membership, multi-IP disambiguation, 0-IP identity-only) but reports failures
per-side via ``compare_side_invalid`` so an ambiguous side highlights its own
column instead of failing the whole comparison as an opaque error.

The backend never trusts a client-supplied ``source_ip``: when a side names a
user, the IP must belong to that user's active or assigned addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Protocol

from ..errors import compare_side_invalid
from ..ngfw import endpoints as ep
from ..ngfw import schemas as S
from ..ngfw.client import NgfwClient
from .access_compare import ResolvedSubject
from .binding_pool import RulesSnapshot
from .user_sessions import user_source_addresses


class SubjectInput(Protocol):
    """The per-side request shape (``CompareSubject``)."""

    user_id: str | None
    source_ip: str | None


def _resolve_user(snapshot: RulesSnapshot, side: str, user_id: str | None) -> S.NgfwUser | None:
    if not user_id:
        return None
    for user in snapshot.users:
        if str(user.id) == str(user_id):
            return user
    raise compare_side_invalid(side, "unknown_user", user_id=user_id)


def _parse_source_ip(side: str, raw: str | None) -> str | None:
    if not raw or not raw.strip():
        return None
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError as exc:
        raise compare_side_invalid(side, "invalid_source_ip", source_ip=raw) from exc


def _finalize_source_ip(
    side: str,
    user: S.NgfwUser | None,
    source_ip: str | None,
    sessions: list[S.AuthSession],
    auth_rules: list[S.AuthRule],
) -> str | None:
    """Validate/select the side's source IP against the user's live addresses.

    Without a user there is nothing to bind against, so a well-formed IP is used
    as-is. With a user: an explicit IP must be active or assigned; a single
    available IP is auto-selected; several require an explicit choice (per-side
    ``multiple_source_ips``); none is valid and yields identity-only (``None``).
    """
    if user is None:
        return source_ip

    addresses = user_source_addresses(sessions, auth_rules, str(user.id))
    available = {item["ip"] for item in addresses}

    if source_ip is not None:
        if source_ip not in available:
            raise compare_side_invalid(side, "source_ip_not_assigned", source_ip=source_ip, user_id=str(user.id))
        return source_ip

    if len(available) == 1:
        return next(iter(available))
    if len(available) > 1:
        raise compare_side_invalid(side, "multiple_source_ips", source_ips=sorted(available), user_id=str(user.id))
    return None


async def resolve_compare_subjects(
    snapshot: RulesSnapshot,
    client: NgfwClient,
    a_input: SubjectInput,
    b_input: SubjectInput,
) -> tuple[ResolvedSubject, ResolvedSubject]:
    """Resolve both side subjects, batching the live auth reads into one gather.

    User lookup and IP parsing are pure (snapshot-only) and run first so a bad
    subject fails before any NGFW read. The live auth sessions/rules — needed
    only when at least one side names a user — are read once (a single gather)
    and shared by both sides (NFR-3).
    """
    user_a = _resolve_user(snapshot, "a", a_input.user_id)
    user_b = _resolve_user(snapshot, "b", b_input.user_id)
    ip_a = _parse_source_ip("a", a_input.source_ip)
    ip_b = _parse_source_ip("b", b_input.source_ip)

    sessions: list[S.AuthSession] = []
    auth_rules: list[S.AuthRule] = []
    if user_a is not None or user_b is not None:
        sessions, auth_rules = await asyncio.gather(
            ep.get_auth_sessions(client),
            ep.get_auth_rules(client),
        )

    ip_a = _finalize_source_ip("a", user_a, ip_a, sessions, auth_rules)
    ip_b = _finalize_source_ip("b", user_b, ip_b, sessions, auth_rules)
    return ResolvedSubject(user_a, ip_a), ResolvedSubject(user_b, ip_b)

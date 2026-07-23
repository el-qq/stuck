"""User listing endpoint: GET /api/users (docs/API_CONTRACT.md)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query

from ..deps import (
    current_session,
    get_binding_pool,
    get_or_load_snapshot,
    ngfw_client_for,
)
from ..domain.binding_pool import BindingPool
from ..domain.session_store import Session
from ..domain.user_sessions import (
    user_source_addresses as collect_user_source_addresses,
)
from ..errors import not_found
from ..ngfw import endpoints as ep

router = APIRouter(prefix="/api", tags=["users"])

_ALLOWED_DOMAIN_TYPES = {"local", "ad", "ald", "freeipa", "radius", "device"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/users")
async def list_users(
    search: str | None = Query(default=None),
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
):
    was_cached = pool.has_snapshot(session.admin_login, session.server)
    snap = await get_or_load_snapshot(session, pool)

    needle = (search or "").strip().lower()
    users = []
    for u in snap.users:
        if needle and needle not in u.name.lower() and needle not in u.login.lower():
            continue
        domain_type = u.domain_type if u.domain_type in _ALLOWED_DOMAIN_TYPES else "local"
        users.append(
            {
                "id": str(u.id),
                "name": u.name,
                "login": u.login,
                "enabled": bool(u.enabled),
                "domain_type": domain_type,
                "group_id": str(u.parent_id) if u.parent_id else None,
                "comment": u.comment or None,
            }
        )

    return {
        "users": users,
        # (v2) renamed from loaded_at.
        "rules_updated_at": _iso(snap.loaded_at),
        "cached": was_cached,
    }


@router.get("/users/{user_id}/source-addresses")
async def user_source_addresses(
    user_id: str,
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
):
    """Return live and configured source IPs; this response is never cached."""

    snap = await get_or_load_snapshot(session, pool)
    if not any(str(user.id) == str(user_id) for user in snap.users):
        raise not_found("Unknown user_id", user_id=user_id)

    client = ngfw_client_for(session)
    sessions, auth_rules = await asyncio.gather(
        ep.get_auth_sessions(client),
        ep.get_auth_rules(client),
    )
    return {
        "user_id": user_id,
        "addresses": collect_user_source_addresses(sessions, auth_rules, user_id),
    }

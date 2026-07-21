"""Authentication endpoints: login, logout.

Contract: docs/API_CONTRACT.md.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..deps import (
    SESSION_COOKIE,
    get_binding_pool,
    get_session_store,
)
from ..domain.binding_pool import BindingPool
from ..domain.admin_access import AdminAccessProfile
from ..domain.ngfw_access import normalize_server
from ..domain.session_store import Session, SessionStore
from ..errors import StuckError
from ..logging_setup import log_event
from ..ngfw.client import ngfw_login, ngfw_logout, ngfw_whoami

_auth_log = logging.getLogger("stuck.auth")
_pool_log = logging.getLogger("stuck.pool")

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    login: str = Field(min_length=1)
    password: str = Field(min_length=1)
    server: str = Field(min_length=1)


def _set_session_cookie(response: Response, session: Session, settings: Settings) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session.session_id,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
        path="/",
    )


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.post("/login")
async def login(
    body: LoginRequest,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_session_store),
    pool: BindingPool = Depends(get_binding_pool),
):
    server = normalize_server(body.server)
    configured_server = (
        normalize_server(settings.STUCK_DEFAULT_SERVER) if settings.STUCK_DEFAULT_SERVER.strip() else None
    )
    if configured_server is not None and server != configured_server:
        raise StuckError(
            "ngfw_host_not_allowed",
            "This STUCK server is locked to its configured default NGFW host",
        )

    # Login ALWAYS validates the password against the NGFW (contract v2 §3.1),
    # even when the binding's rules snapshot is already pooled.
    ngfw_cookies = await ngfw_login(server, body.login, body.password)
    try:
        # Before a STUCK session exists, inspect the authenticated NGFW role.
        # A 401/403 here is the documented provisional-cookie 2FA signal.
        admin_access: AdminAccessProfile = await ngfw_whoami(server, ngfw_cookies, provisional=True)
    except Exception:
        # Do not leave a successful password-login session behind when role
        # verification cannot complete.  No secret is logged or returned.
        await ngfw_logout(server, ngfw_cookies)
        raise

    # v2.1: NGFW cookies live only in the STUCK session; the pool keeps just
    # the rules snapshot (+ its timestamp) and survives logout.
    # Use NGFW's canonical identity as the session/pool key.  The submitted
    # spelling may differ by case or an authenticated directory alias.
    session = store.create(admin_access.login, server, ngfw_cookies, admin_access)
    _set_session_cookie(response, session, settings)

    if admin_access.trace_allowed:
        binding, created = pool.ensure(session.admin_login, server)
        first_login = binding.snapshot is None
        rules_updated_at = binding.rules_updated_at
        log_event(
            _pool_log,
            "binding_created" if created else "binding_reused",
            login=session.admin_login,
            server=server,
            rules_updated_at=_iso(rules_updated_at) if rules_updated_at else None,
        )
    else:
        # Ensure no previous higher-privilege login for this pair remains in
        # the in-memory pool while the current role is insufficient.
        pool.discard(session.admin_login, server)
        first_login = False
        rules_updated_at = None
    log_event(
        _auth_log,
        "login_success",
        login=session.admin_login,
        server=server,
        first_login=first_login,
        trace_allowed=admin_access.trace_allowed,
    )

    return {
        "ok": True,
        "session": {
            "login": session.admin_login,
            "server": server,
            "expires_at": _iso(session.expires_at),
            "first_login": first_login,
            "rules_updated_at": _iso(rules_updated_at) if rules_updated_at else None,
        },
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_session_store),
):
    # Idempotent: succeed even without a valid session.
    # (v2.1) The STUCK session and its NGFW cookie die; the NGFW admin session
    # is killed best-effort (cookie is never reused, don't leave it orphaned).
    # The binding pool (rules snapshot + rules_updated_at) is left intact.
    sid = request.cookies.get(SESSION_COOKIE)
    session = store.delete(sid)
    if session is not None:
        await ngfw_logout(session.server, session.ngfw_cookies)
        log_event(
            _auth_log,
            "logout",
            login=session.admin_login,
            server=session.server,
        )

    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
    )
    return {"ok": True}

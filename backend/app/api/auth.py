"""Thin HTTP router for login, logout and second-factor authentication.

Cookie mutation, session finalization and the WebSocket-driven 2FA state
machine are isolated in sibling modules.  This router remains the stable home
for the public request models and channel factory so existing integrations and
tests can keep importing and patching this module.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..deps import (
    PENDING_2FA_COOKIE,
    SESSION_COOKIE,
    get_binding_pool,
    get_pending_2fa_store,
    get_session_store,
)
from ..domain.admin_access import AdminAccessProfile, TwoFactorPending, require_readonly_admin
from ..domain.binding_pool import BindingPool
from ..domain.ngfw_access import normalize_server
from ..domain.pending_2fa import PendingTwoFactorStore
from ..domain.session_store import SessionStore
from ..errors import StuckError
from ..logging_setup import log_event
from ..ngfw.client import ngfw_login, ngfw_logout, ngfw_whoami_probe
from ..ngfw.two_factor_ws import NgfwTwoFactorChannel
from .auth_session import begin_two_factor, clear_session_cookie, finalize_login
from .auth_two_factor import cancel_two_factor, discard_pending, submit_two_factor

_auth_log = logging.getLogger("stuck.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    login: str = Field(min_length=1)
    password: str = Field(min_length=1)
    server: str = Field(min_length=1)


class TwoFactorRequest(BaseModel):
    """The code-only body of ``POST /api/auth/2fa``.

    The pending challenge is looked up exclusively through the HttpOnly cookie;
    neither a password nor an NGFW cookie can arrive in this request body.
    """

    code: str = Field(min_length=1)


@router.post("/login")
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_session_store),
    pool: BindingPool = Depends(get_binding_pool),
    pending_store: PendingTwoFactorStore = Depends(get_pending_2fa_store),
):
    """Authenticate a password, then create a session or begin the 2FA branch."""
    # A new password attempt replaces an abandoned challenge before it talks to
    # NGFW. This prevents a stale socket from blocking the next challenge.
    await discard_pending(pending_store, request.cookies.get(PENDING_2FA_COOKIE))

    server = normalize_server(body.server)
    configured_server = (
        normalize_server(settings.STUCK_DEFAULT_SERVER) if settings.STUCK_DEFAULT_SERVER.strip() else None
    )
    if configured_server is not None and server != configured_server:
        raise StuckError(
            "ngfw_host_not_allowed",
            "This STUCK server is locked to its configured default NGFW host",
        )

    # Login always verifies the password even when a non-secret rules snapshot
    # for this administrator/server pair is already cached.
    ngfw_cookies = await ngfw_login(server, body.login, body.password)
    try:
        role = await ngfw_whoami_probe(server, ngfw_cookies, submitted_login=body.login)
    except Exception:
        await ngfw_logout(server, ngfw_cookies)
        raise

    if isinstance(role, TwoFactorPending):
        return await begin_two_factor(role, server, ngfw_cookies, response, settings, pending_store)

    admin_access: AdminAccessProfile = role
    if settings.STUCK_REQUIRE_READONLY_ADMIN:
        try:
            require_readonly_admin(admin_access)
        except StuckError:
            await ngfw_logout(server, ngfw_cookies)
            log_event(
                _auth_log,
                "login_rejected_readonly_required",
                login=admin_access.login,
                server=server,
            )
            raise
    return finalize_login(response, settings, store, pool, server, ngfw_cookies, admin_access)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_session_store),
):
    """Idempotently destroy a STUCK/NGFW session while retaining its snapshot."""
    session = store.delete(request.cookies.get(SESSION_COOKIE))
    if session is not None:
        await ngfw_logout(session.server, session.ngfw_cookies)
        log_event(_auth_log, "logout", login=session.admin_login, server=session.server)
    clear_session_cookie(response, settings)
    return {"ok": True}


@router.post("/2fa")
async def submit_two_factor_route(
    body: TwoFactorRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_session_store),
    pool: BindingPool = Depends(get_binding_pool),
    pending_store: PendingTwoFactorStore = Depends(get_pending_2fa_store),
):
    """Submit a code through the isolated first-class 2FA workflow."""
    return await submit_two_factor(
        code=body.code,
        pending_id=request.cookies.get(PENDING_2FA_COOKIE),
        response=response,
        settings=settings,
        store=store,
        pool=pool,
        pending_store=pending_store,
        # Kept as a router-level dependency so test monkeypatches and any
        # future alternate transport continue to affect the workflow.
        channel_factory=NgfwTwoFactorChannel,
    )


@router.post("/2fa/cancel")
async def cancel_two_factor_route(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    pending_store: PendingTwoFactorStore = Depends(get_pending_2fa_store),
):
    """Idempotently end a pending challenge and return to password login."""
    return await cancel_two_factor(
        pending_id=request.cookies.get(PENDING_2FA_COOKIE),
        response=response,
        settings=settings,
        pending_store=pending_store,
    )

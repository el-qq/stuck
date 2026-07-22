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
    PENDING_2FA_COOKIE,
    SESSION_COOKIE,
    get_binding_pool,
    get_pending_2fa_store,
    get_session_store,
)
from ..domain.binding_pool import BindingPool
from ..domain.admin_access import AdminAccessProfile, TwoFactorPending
from ..domain.ngfw_access import normalize_server
from ..domain.pending_2fa import PendingTwoFactorStore
from ..domain.session_store import Session, SessionStore
from ..errors import StuckError, second_factor_expired, second_factor_invalid
from ..logging_setup import log_event
from ..ngfw.client import ngfw_login, ngfw_logout, ngfw_whoami_probe
from ..ngfw.two_factor_ws import MSG_CANCELLED, MSG_CHALLENGE, MSG_CLOSED, NgfwTwoFactorChannel

_auth_log = logging.getLogger("stuck.auth")
_pool_log = logging.getLogger("stuck.pool")

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    login: str = Field(min_length=1)
    password: str = Field(min_length=1)
    server: str = Field(min_length=1)


class TwoFactorRequest(BaseModel):
    """Body of ``POST /api/auth/2fa`` — just the code the admin typed.

    The pending challenge is located from the HttpOnly ``stuck_2fa`` cookie, not
    the body, so no server/login is resent. ``code`` is a secret: never log it.
    """

    code: str = Field(min_length=1)


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


def _set_pending_2fa_cookie(response: Response, pending_id: str, settings: Settings) -> None:
    """Set the short-lived ``stuck_2fa`` cookie carrying the opaque pending id.

    Same flags as the session cookie but Max-Age = STUCK_2FA_TTL_SECONDS. Only
    one of ``stuck_session`` / ``stuck_2fa`` is ever set on a response.
    """
    response.set_cookie(
        key=PENDING_2FA_COOKIE,
        value=pending_id,
        max_age=settings.STUCK_2FA_TTL_SECONDS,
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
        path="/",
    )


def _clear_pending_2fa_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=PENDING_2FA_COOKIE,
        path="/",
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
    )


async def _resolve_provisional_role(
    server: str,
    ngfw_cookies: dict[str, str],
    submitted_login: str,
) -> AdminAccessProfile | TwoFactorPending:
    """Resolve the authenticated role right after a provisional password login.

    Seam for the 2FA branch: returns :class:`TwoFactorPending` when NGFW answers
    a 200 whoami that is blocked awaiting a second factor, otherwise the strict
    :class:`AdminAccessProfile`.
    """
    return await ngfw_whoami_probe(server, ngfw_cookies, submitted_login=submitted_login)


async def _begin_two_factor(
    pending: TwoFactorPending,
    server: str,
    ngfw_cookies: dict[str, str],
    response: Response,
    settings: Settings,
    pending_store: PendingTwoFactorStore,
) -> dict[str, object]:
    """Register a pending 2FA challenge and arm the ``stuck_2fa`` cookie.

    No WebSocket is opened here: the whole challenge (open → start → challenge →
    code → result) runs later inside ``POST /api/auth/2fa`` per attempt. Keeping
    login WebSocket-free means a locked/erroring challenge can never fail the
    login itself, so the admin can always reach the code form and re-authenticate
    (multiple devices each get their own opaque ``pending_id``).

    Returns the ``two_factor_required`` login response (no session, no secrets).
    """
    entry = pending_store.create(
        server,
        ngfw_cookies,
        pending.submitted_login,
        pending.admin_id,
    )
    _set_pending_2fa_cookie(response, entry.pending_id, settings)
    log_event(_auth_log, "two_factor_required", server=server)
    return {
        "ok": True,
        "two_factor_required": True,
        "expires_at": _iso(entry.expires_at),
        "message": pending.message or None,
    }


def _finalize_login(
    response: Response,
    settings: Settings,
    store: SessionStore,
    pool: BindingPool,
    server: str,
    ngfw_cookies: dict[str, str],
    admin_access: AdminAccessProfile,
) -> dict[str, object]:
    """Create the STUCK session for an authenticated role; return ``{ok, session}``.

    Shared by password login and completed-2FA login: sets ``stuck_session``,
    ensures or discards the rules-snapshot binding by role, and logs the outcome.
    """
    # v2.1: NGFW cookies live only in the STUCK session; the pool keeps just the
    # rules snapshot (+ its timestamp) and survives logout. Use NGFW's canonical
    # identity as the session/pool key (submitted spelling may differ by case).
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
        # Ensure no previous higher-privilege login for this pair remains in the
        # in-memory pool while the current role is insufficient.
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


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    # This browser may still hold a previous 2FA challenge (stale stuck_2fa cookie)
    # — e.g. after abandoning or exhausting one. Tear its socket + provisional NGFW
    # session down BEFORE starting a new login, so each 2FA attempt gets a truly
    # fresh challenge (NGFW rejects a new challenge while an old one lingers).
    stale = pending_store.pop(request.cookies.get(PENDING_2FA_COOKIE))
    if stale is not None:
        if stale.channel is not None:
            await stale.channel.close()
        await ngfw_logout(stale.server, stale.ngfw_cookies)

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
        # A 401/403 here is the documented provisional-cookie 2FA signal; a 200
        # blocked profile is the new "code required" branch (mfa2-plan.md §2).
        role = await _resolve_provisional_role(server, ngfw_cookies, body.login)
    except Exception:
        # Do not leave a successful password-login session behind when role
        # verification cannot complete.  No secret is logged or returned.
        await ngfw_logout(server, ngfw_cookies)
        raise

    if isinstance(role, TwoFactorPending):
        # Blocked awaiting a code: hand off to the challenge flow. The provisional
        # NGFW cookies are moved into the pending entry (not a STUCK session), so
        # ownership of ``ngfw_cookies`` transfers to ``_begin_two_factor`` and it
        # must clean them up (logout) on any challenge-open failure.
        return await _begin_two_factor(role, server, ngfw_cookies, response, settings, pending_store)

    admin_access: AdminAccessProfile = role
    return _finalize_login(response, settings, store, pool, server, ngfw_cookies, admin_access)


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


@router.post("/2fa")
async def submit_two_factor(
    body: TwoFactorRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_session_store),
    pool: BindingPool = Depends(get_binding_pool),
    pending_store: PendingTwoFactorStore = Depends(get_pending_2fa_store),
):
    """Complete a 2FA login by submitting the code (docs/API_CONTRACT.md).

    Runs the ENTIRE challenge over a fresh WebSocket per attempt: open → send
    ``2fa_start`` → receive ``2fa_challenge`` → send the code → read the result,
    then close. Nothing is held between requests, so retries and multiple devices
    are independent and re-login always starts clean.

    Success mirrors ``/login``: creates the real STUCK session and returns the
    same ``{ok, session}`` object, swapping ``stuck_2fa`` for ``stuck_session``.

    A rejected code (``2fa_error``) keeps the pending entry and its cookie so the
    admin can retry (NGFW itself gates how many attempts are allowed); only an
    expired/missing pending clears the cookie. No secret (code, cookies, session
    id) ever appears in the response or logs.
    """
    pid = request.cookies.get(PENDING_2FA_COOKIE)
    entry = pending_store.get(pid)
    if entry is None:
        _clear_pending_2fa_cookie(response, settings)
        raise second_factor_expired()

    async def _reset_to_login() -> None:
        # Give up: drop the pending entry, close the held socket + provisional NGFW
        # session, clear the cookie. The frontend treats ``second_factor_expired``
        # as "return to the login screen".
        pending_store.pop(pid)
        if entry.channel is not None:
            await entry.channel.close()
        await ngfw_logout(entry.server, entry.ngfw_cookies)
        _clear_pending_2fa_cookie(response, settings)

    # ONE socket serves the whole 2FA session (observed on the NGFW web UI). Each
    # attempt re-initiates on it: client sends ``2fa_start`` → server replies
    # ``2fa_challenge`` → client sends the code → server replies ``2fa_error`` /
    # success. The server does NOT auto re-challenge after an error — the next
    # ``2fa_start`` is what prompts a fresh challenge. The socket is held on the
    # pending entry across attempts; the frontend closes it after its retry limit.
    recv_timeout = float(settings.STUCK_NGFW_TIMEOUT_SECONDS)
    reached_challenge = False
    verdict = None
    role: AdminAccessProfile | TwoFactorPending | None = None
    try:
        channel = entry.channel
        if channel is None:
            channel = NgfwTwoFactorChannel(entry.server, entry.ngfw_cookies)
            await channel.open()
            entry.channel = channel

        await channel.send_start()
        for _ in range(4):
            msg = await channel.recv_typed(timeout=recv_timeout)
            if msg.type == MSG_CHALLENGE:
                reached_challenge = True
                break
            if msg.is_error or msg.type in (MSG_CANCELLED, MSG_CLOSED):
                break
        if reached_challenge:
            await channel.send_code(body.code)
            verdict = await channel.recv_typed(timeout=recv_timeout)
            if not verdict.is_error:
                # Success candidate (2fa_success or a clean close): confirm via a
                # fresh whoami — blocked_flags == 0 with a real role is the truth.
                role = await ngfw_whoami_probe(entry.server, entry.ngfw_cookies, submitted_login=entry.submitted_login)
    except StuckError:
        await _reset_to_login()
        raise second_factor_expired() from None

    if not reached_challenge:
        # NGFW would not start a challenge (e.g. a previous one is still winding
        # down, or the account is locked). Drop the pending and reset to login.
        await _reset_to_login()
        raise second_factor_expired()

    if verdict.is_error and not verdict.can_retry:
        # NGFW's own terminal rejection (its retry limit) → reset to login.
        await _reset_to_login()
        raise second_factor_expired()

    if verdict.is_error or isinstance(role, TwoFactorPending):
        # Wrong code but retryable: KEEP the socket open on the pending entry for
        # the next attempt (which re-sends ``2fa_start``). STUCK imposes no cap —
        # the frontend closes the challenge after its retry limit.
        message = verdict.message if (verdict.is_error and verdict.message) else ""
        raise second_factor_invalid(can_retry=True, message=message)

    # Accepted: the provisional cookies become the real session's; close the WS.
    pending_store.pop(pid)
    if entry.channel is not None:
        await entry.channel.close()
    result_body = _finalize_login(response, settings, store, pool, entry.server, entry.ngfw_cookies, role)
    _clear_pending_2fa_cookie(response, settings)
    return result_body


@router.post("/2fa/cancel")
async def cancel_two_factor(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    pending_store: PendingTwoFactorStore = Depends(get_pending_2fa_store),
):
    """Abort an in-flight 2FA challenge (idempotent, mirrors ``/logout``).

    Always returns ``{"ok": True}`` and clears ``stuck_2fa``, even with no
    pending entry, so the UI can safely return to the login screen. The
    abandoned provisional NGFW session is closed best-effort.
    """
    pid = request.cookies.get(PENDING_2FA_COOKIE)
    entry = pending_store.pop(pid)
    if entry is not None:
        if entry.channel is not None:
            await entry.channel.close()
        await ngfw_logout(entry.server, entry.ngfw_cookies)
        log_event(_auth_log, "two_factor_cancelled", server=entry.server)
    _clear_pending_2fa_cookie(response, settings)
    return {"ok": True}

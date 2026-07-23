"""Cookie and authenticated-session transitions for the auth API.

These helpers deliberately live next to the HTTP router: they construct the
public response shapes and set HttpOnly browser cookies, while the domain stores
remain transport-agnostic.  NGFW cookies are accepted only as backend-local
values and are never included in a returned object or log event.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Response

from ..config import Settings
from ..deps import PENDING_2FA_COOKIE, SESSION_COOKIE
from ..domain.admin_access import AdminAccessProfile, TwoFactorPending
from ..domain.binding_pool import BindingPool
from ..domain.pending_2fa import PendingTwoFactorStore
from ..domain.session_store import Session, SessionStore
from ..logging_setup import log_event

_auth_log = logging.getLogger("stuck.auth")
_pool_log = logging.getLogger("stuck.pool")


def iso_timestamp(timestamp: float) -> str:
    """Serialize an in-memory timestamp in the API's stable UTC format."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_session_cookie(response: Response, session: Session, settings: Settings) -> None:
    """Set the opaque STUCK session cookie with the configured security flags."""
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session.session_id,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    """Invalidate the browser session cookie without touching the rule snapshot."""
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
    )


def set_pending_two_factor_cookie(response: Response, pending_id: str, settings: Settings) -> None:
    """Set the short-lived opaque 2FA identifier; never a code or NGFW cookie."""
    response.set_cookie(
        key=PENDING_2FA_COOKIE,
        value=pending_id,
        max_age=settings.STUCK_2FA_TTL_SECONDS,
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
        path="/",
    )


def clear_pending_two_factor_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=PENDING_2FA_COOKIE,
        path="/",
        httponly=True,
        secure=settings.STUCK_COOKIE_SECURE,
        samesite=settings.STUCK_COOKIE_SAMESITE,
    )


async def begin_two_factor(
    pending: TwoFactorPending,
    server: str,
    ngfw_cookies: dict[str, str],
    response: Response,
    settings: Settings,
    pending_store: PendingTwoFactorStore,
) -> dict[str, object]:
    """Persist a pending 2FA challenge and return the public login branch.

    The password-login request never opens the WebSocket.  This keeps a failed
    challenge from making the code-entry screen unreachable and ensures every
    device receives an independent opaque pending identifier.
    """
    entry = pending_store.create(server, ngfw_cookies, pending.submitted_login, pending.admin_id)
    set_pending_two_factor_cookie(response, entry.pending_id, settings)
    log_event(_auth_log, "two_factor_required", server=server)
    return {
        "ok": True,
        "two_factor_required": True,
        "expires_at": iso_timestamp(entry.expires_at),
        "message": pending.message or None,
    }


def finalize_login(
    response: Response,
    settings: Settings,
    store: SessionStore,
    pool: BindingPool,
    server: str,
    ngfw_cookies: dict[str, str],
    admin_access: AdminAccessProfile,
) -> dict[str, object]:
    """Create the real STUCK session after a verified password or 2FA login.

    The binding pool gets only a snapshot binding.  Its relationship to the
    active session deliberately contains no NGFW secrets and survives logout.
    """
    session = store.create(admin_access.login, server, ngfw_cookies, admin_access)
    set_session_cookie(response, session, settings)

    if admin_access.trace_allowed:
        binding, created = pool.ensure(session.admin_login, server)
        first_login = binding.snapshot is None
        rules_updated_at = binding.rules_updated_at
        log_event(
            _pool_log,
            "binding_created" if created else "binding_reused",
            login=session.admin_login,
            server=server,
            rules_updated_at=iso_timestamp(rules_updated_at) if rules_updated_at else None,
        )
    else:
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
            "expires_at": iso_timestamp(session.expires_at),
            "first_login": first_login,
            "rules_updated_at": iso_timestamp(rules_updated_at) if rules_updated_at else None,
        },
    }

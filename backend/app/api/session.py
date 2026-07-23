"""Session status endpoint: GET /api/session (docs/API_CONTRACT.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from ..config import Settings, get_settings
from ..deps import (
    PENDING_2FA_COOKIE,
    SESSION_COOKIE,
    current_session,
    get_binding_pool,
    get_pending_2fa_store,
    get_session_store,
)
from ..domain.binding_pool import BindingPool
from ..domain.pending_2fa import PendingTwoFactorStore
from ..domain.session_store import Session, SessionStore
from ..errors import not_authenticated, session_expired
from ..ngfw.client import ngfw_whoami

router = APIRouter(prefix="/api", tags=["session"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _access_payload(session: Session) -> dict[str, str | bool]:
    return session.admin_access.public()


@router.get("/session")
async def session_status(
    request: Request,
    store: SessionStore = Depends(get_session_store),
    pending_store: PendingTwoFactorStore = Depends(get_pending_2fa_store),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    """Report the current backend-held auth state so the browser can restore it.

    Three outcomes: an authenticated session, a live 2FA challenge (page reloaded
    between password and code — resume the code form), or nothing.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    session, expired = store.resolve(sid)
    if expired:
        raise session_expired()
    if session is None:
        # No STUCK session, but an in-flight 2FA challenge (the browser reloaded
        # after the password step) must resume the code form, not a fresh login.
        pending = pending_store.get(request.cookies.get(PENDING_2FA_COOKIE))
        if pending is not None:
            return {
                "authenticated": False,
                "two_factor_pending": True,
                "expires_at": _iso(pending.expires_at),
            }
        raise not_authenticated()

    binding = pool.get(session.admin_login, session.server)
    rules_updated_at = binding.rules_updated_at if binding else None
    return {
        "authenticated": True,
        "login": session.admin_login,
        "server": session.server,
        "expires_at": _iso(session.expires_at),
        "rules_loaded": rules_updated_at is not None,
        "rules_updated_at": _iso(rules_updated_at) if rules_updated_at else None,
        # Safe, reduced role profile.  Never expose the NGFW whoami body,
        # competence list, cookies or internal endpoint details.
        "access_profile": _access_payload(session),
        # The frontend uses this non-secret connection metadata solely to
        # build a hyperlink to the corresponding NGFW administration section.
        "ngfw_port": settings.STUCK_NGFW_PORT,
        # frontend shows the "Export rules" button only when true.
        "rules_export_enabled": settings.STUCK_ENABLE_RULES_EXPORT,
        # frontend shows the "Rule hygiene" panel only when true.
        "rule_hygiene_enabled": settings.STUCK_ENABLE_RULE_HYGIENE,
        # frontend shows the "Snapshots" panel only when true.
        "rule_snapshots_enabled": settings.STUCK_ENABLE_RULE_SNAPSHOTS,
    }


@router.post("/session/access/refresh")
async def refresh_access_profile(
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
):
    """Re-read the current admin role using the active, server-side cookie."""

    session.admin_access = await ngfw_whoami(session.server, session.ngfw_cookies)
    if not session.admin_access.trace_allowed:
        # A role can change while the browser session is alive.  Clear any
        # previously cached snapshot immediately so an insufficient role has
        # neither a binding nor a misleading ``rules_loaded`` status.
        pool.discard(session.admin_login, session.server)
    return {"ok": True, "access_profile": _access_payload(session)}

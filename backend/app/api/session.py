"""Session status endpoint: GET /api/session (docs/API_CONTRACT.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from ..config import Settings, get_settings
from ..deps import current_session, get_binding_pool
from ..domain.binding_pool import BindingPool
from ..domain.session_store import Session
from ..ngfw.client import ngfw_whoami

router = APIRouter(prefix="/api", tags=["session"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _access_payload(session: Session) -> dict[str, str | bool]:
    return session.admin_access.public()


@router.get("/session")
async def session_status(
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
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
        # (v2.3) frontend shows the "Export rules" button only when true.
        "rules_export_enabled": settings.STUCK_ENABLE_RULES_EXPORT,
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

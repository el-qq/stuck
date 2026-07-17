"""Session status endpoint: GET /api/session (docs/API_CONTRACT.md)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from ..config import Settings, get_settings
from ..deps import current_session, get_binding_pool
from ..domain.binding_pool import BindingPool
from ..domain.session_store import Session

router = APIRouter(prefix="/api", tags=["session"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        # (v2.3) frontend shows the "Export rules" button only when true.
        "rules_export_enabled": settings.STUCK_ENABLE_RULES_EXPORT,
    }

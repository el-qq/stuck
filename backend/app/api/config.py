"""Public, non-sensitive frontend bootstrap configuration."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import Settings, get_settings

router = APIRouter(prefix="/api", tags=["config"])


@router.get("/config")
async def public_config(settings: Settings = Depends(get_settings)):
    """Return values the browser needs before an administrator signs in."""
    return {"default_server": settings.STUCK_DEFAULT_SERVER}

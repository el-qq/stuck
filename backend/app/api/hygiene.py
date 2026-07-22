"""Rule-hygiene endpoint (docs/API_CONTRACT.md).

Static, read-only structural analysis of the current firewall snapshot:
shadowed / redundant / unreachable / overly-broad rules. Gated by
``STUCK_ENABLE_RULE_HYGIENE`` exactly like the rules export.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from ..config import Settings, get_settings
from ..deps import current_session, get_binding_pool, get_or_load_snapshot
from ..domain import rule_hygiene
from ..domain.binding_pool import BindingPool
from ..domain.session_store import Session
from ..errors import StuckError
from ..logging_setup import log_event

_hygiene_log = logging.getLogger("stuck.hygiene")

router = APIRouter(prefix="/api", tags=["hygiene"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/rules/hygiene")
async def rules_hygiene(
    refresh: bool = Query(default=False),
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    # Gated: when disabled, behave as a non-existent route (do not disclose it).
    if not settings.STUCK_ENABLE_RULE_HYGIENE:
        raise StuckError("not_found", "Not found")

    # ?refresh=true → re-pull via the ACTIVE session's NGFW cookie, like export.
    snap = await get_or_load_snapshot(session, pool, force=refresh)
    report = rule_hygiene.analyze_snapshot(snap)

    log_event(
        _hygiene_log,
        "rules_hygiene",
        server=session.server,
        login=session.admin_login,
        refresh=refresh,
        rules_updated_at=_iso(snap.loaded_at),
        findings=report["summary"]["total"],
    )

    return {
        # Binding comes from the SESSION only — never from the request (§3.8).
        "binding": {"admin": session.admin_login, "server": session.server},
        "rules_updated_at": _iso(snap.loaded_at),
        "generated_at": _iso(datetime.now(tz=timezone.utc).timestamp()),
        "summary": report["summary"],
        "findings": report["findings"],
    }

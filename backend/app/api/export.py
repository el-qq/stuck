"""Rules export endpoint: GET /api/rules/export (docs/API_CONTRACT.md).

Diagnostic feature, gated by ``STUCK_ENABLE_RULES_EXPORT`` (default True). When
disabled the endpoint answers 404 — as if it did not exist — so its presence is
not discoverable.

HARD ISOLATION INVARIANT (§3.8): the exported binding (admin + server) is taken
EXCLUSIVELY from the server-side session (``stuck_session``), never from request
params/body/headers. ``?user_id`` is a filter over NGFW end-users WITHIN the
current binding's snapshot; an unknown user_id → 404 not_found. From admin B's
session it is impossible to reach admin A's (or another server's) rules.

The export carries NO secrets: the binding pool holds only the rules snapshot
(no NGFW cookie, no password), and every serialized value comes from that
snapshot via pydantic ``model_dump`` — nothing pulls in session cookies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from ..config import Settings, get_settings
from ..deps import current_session, get_binding_pool, get_or_load_snapshot
from ..domain import trace_engine
from ..domain.binding_pool import BindingPool, RulesSnapshot
from ..domain.session_store import Session
from ..errors import StuckError
from ..logging_setup import log_event
from ..ngfw import schemas as S

_export_log = logging.getLogger("stuck.export")

router = APIRouter(prefix="/api", tags=["export"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dump(models) -> list[dict[str, Any]]:
    return [m.model_dump(mode="json") for m in models]


def _find_user(snap: RulesSnapshot, user_id: str) -> S.NgfwUser:
    for u in snap.users:
        if str(u.id) == str(user_id):
            return u
    # Not a channel to probe other bindings: only the current binding's snapshot.
    raise StuckError("not_found", "Unknown user_id", details={"user_id": user_id})


def _build_snapshot(
    snap: RulesSnapshot,
    filtered: Optional[dict[str, list[Any]]],
    only_user: Optional[S.NgfwUser],
) -> dict[str, Any]:
    """Serialize the snapshot into the stable documented export schema (no secrets).

    ``filtered`` (from trace_engine.rules_applicable_to_user) narrows the rule
    lists to a single user; when None the full snapshot is exported.
    """
    fw_fwd = filtered["fw_forward"] if filtered else snap.fw_forward
    fw_inp = filtered["fw_input"] if filtered else snap.fw_input
    fw_dnat = filtered["fw_dnat"] if filtered else snap.fw_dnat
    fw_snat = filtered["fw_snat"] if filtered else snap.fw_snat
    cf_rules = filtered["cf_rules"] if filtered else snap.cf_rules
    ips_bypass = filtered["ips_bypass"] if filtered else snap.ips_bypass
    users = [only_user] if only_user is not None else snap.users

    # /aliases/all — NGFW exposes its objects as aliases; the contract's
    # `aliases` and `objects` reference the same dataset here.
    objects = _dump(snap.aliases.values())

    return {
        "users": _dump(users),
        "aliases": objects,
        "firewall_forward": _dump(fw_fwd),
        "firewall_input": _dump(fw_inp),
        "firewall_pre_filter": _dump(snap.fw_pre_filter),
        "firewall_dnat": _dump(fw_dnat),
        "firewall_snat": _dump(fw_snat),
        "firewall_settings": snap.fw_settings.model_dump(mode="json"),
        "hardware": {
            # null settings = the NGFW does not expose hardware filtering.
            "settings": snap.hw_settings.model_dump(mode="json") if snap.hw_settings else None,
            "rules_mac": _dump(snap.hw_rules_mac),
            "rules_src_ip": _dump(snap.hw_rules_src_ip),
            "rules_dst_ip": _dump(snap.hw_rules_dst_ip),
            "rules_src_dst_ip": _dump(snap.hw_rules_src_dst_ip),
        },
        "ngfw_addresses": list(snap.ngfw_addresses),
        # Module on/off flag (engine input); additive to the firewall rule lists.
        "firewall_state": snap.fw_state.model_dump(mode="json"),
        # "правила + состояние CF" (contract §3.8): rules + state + categories,
        # everything the trace engine needs to re-evaluate content filtering.
        "content_filter": {
            "state": snap.cf_state.model_dump(mode="json"),
            "rules": _dump(cf_rules),
            "categories": snap.cf_categories,
        },
        "speed_limit": {
            "state": snap.shaper_state.model_dump(mode="json"),
            "rules": _dump(snap.shaper_rules),
        },
        "ips_state": snap.ips_state.model_dump(mode="json"),
        "ips_bypass": _dump(ips_bypass),
        "objects": objects,
        # We only cache whether the default AV profile is active.
        "av_profile": {"enabled": snap.av_enabled},
    }


@router.get("/rules/export")
async def rules_export(
    user_id: Optional[str] = Query(default=None),
    refresh: bool = Query(default=False),
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    # Gated: when disabled, behave as a non-existent route (do not disclose it).
    if not settings.STUCK_ENABLE_RULES_EXPORT:
        raise StuckError("not_found", "Not found")

    # ?refresh=true → re-pull via the ACTIVE session's NGFW cookie (like
    # /api/rules/refresh); an expired cookie surfaces as session_expired.
    snap = await get_or_load_snapshot(session, pool, force=refresh)

    filtered_by: Optional[str] = None
    filtered: Optional[dict[str, list[Any]]] = None
    only_user: Optional[S.NgfwUser] = None
    if user_id is not None:
        only_user = _find_user(snap, user_id)  # 404 if not in THIS binding
        filtered = trace_engine.rules_applicable_to_user(snap, only_user)
        filtered_by = str(user_id)

    now = datetime.now(tz=timezone.utc)
    body = {
        # Binding comes from the SESSION only — never from the request (§3.8).
        "binding": {"admin": session.admin_login, "server": session.server},
        "rules_updated_at": _iso(snap.loaded_at),
        "exported_at": _iso(now.timestamp()),
        "filtered_by_user_id": filtered_by,
        "snapshot": _build_snapshot(snap, filtered, only_user),
    }

    ts = now.strftime("%Y%m%dT%H%M%SZ")
    filename = f"rules-{session.server}-{ts}.json"

    log_event(
        _export_log,
        "rules_export",
        server=session.server,
        login=session.admin_login,
        filtered_by_user_id=filtered_by,
        refresh=refresh,
        rules_updated_at=_iso(snap.loaded_at),
    )

    return JSONResponse(
        content=body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

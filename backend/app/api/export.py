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

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Response

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

RULES_EXPORT_FORMAT = "stuck.rules/v2"

# These fields are useful in the product UI, but are neither needed to replay
# the rules nor appropriate for a diagnostic attachment shared outside the
# installation. ``title`` and ``domain_name`` are included because aliases and
# directory domains can reveal the same personal information under other keys.
_ANONYMIZED_FIELDS = frozenset({"comment", "description", "domain_name", "login", "name", "title"})


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dump(models) -> list[dict[str, Any]]:
    return [_dump_one(model) for model in models]


def _dump_one(model) -> dict[str, Any]:
    """Export only fields the trace engine understands, never vendor extras."""
    return model.model_dump(mode="json", include=set(type(model).model_fields))


def _identity_map(snap: RulesSnapshot) -> dict[str, str]:
    """Assign deterministic opaque IDs while preserving rule/user links."""
    replacements: dict[str, str] = {}
    for index, user in enumerate(snap.users, start=1):
        replacements.setdefault(str(user.id), f"user-{index}")

    group_index = 0
    for user in snap.users:
        if user.parent_id is None:
            continue
        group_id = str(user.parent_id)
        if group_id not in replacements:
            group_index += 1
            replacements[group_id] = f"group-{group_index}"
    return replacements


def _anonymize(value: Any, replacements: dict[str, str]) -> Any:
    """Remove display data recursively and replace known user/group IDs."""
    if isinstance(value, dict):
        return {key: _anonymize(item, replacements) for key, item in value.items() if key not in _ANONYMIZED_FIELDS}
    if isinstance(value, list):
        return [_anonymize(item, replacements) for item in value]
    if isinstance(value, str):
        return replacements.get(value, value)
    return value


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
        "firewall_settings": _dump_one(snap.fw_settings),
        "hardware": {
            # null settings = the NGFW does not expose hardware filtering.
            "settings": _dump_one(snap.hw_settings) if snap.hw_settings else None,
            "rules_mac": _dump(snap.hw_rules_mac),
            "rules_src_ip": _dump(snap.hw_rules_src_ip),
            "rules_dst_ip": _dump(snap.hw_rules_dst_ip),
            "rules_src_dst_ip": _dump(snap.hw_rules_src_dst_ip),
        },
        "ngfw_addresses": list(snap.ngfw_addresses),
        # Module on/off flag (engine input); additive to the firewall rule lists.
        "firewall_state": _dump_one(snap.fw_state),
        # "правила + состояние CF" (contract §3.8): rules + state + categories,
        # everything the trace engine needs to re-evaluate content filtering.
        "content_filter": {
            "state": _dump_one(snap.cf_state),
            "rules": _dump(cf_rules),
            "categories": snap.cf_categories,
        },
        "speed_limit": {
            "state": _dump_one(snap.shaper_state),
            "rules": _dump(snap.shaper_rules),
        },
        "ips_state": _dump_one(snap.ips_state),
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
    replacements = _identity_map(snap)
    body = {
        "format": RULES_EXPORT_FORMAT,
        "exported_at": _iso(now.timestamp()),
        "rules_updated_at": _iso(snap.loaded_at),
        # Binding comes from the SESSION only — never from the request (§3.8).
        # The administrator login is deliberately omitted from the attachment.
        "binding": {"server": session.server},
        "filtered_by_user_id": replacements.get(filtered_by, filtered_by) if filtered_by else None,
        "snapshot": _anonymize(_build_snapshot(snap, filtered, only_user), replacements),
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

    return Response(
        content=json.dumps(body, ensure_ascii=False, indent=2) + "\n",
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

"""Trace + rules refresh endpoints (docs/API_CONTRACT.md)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..deps import (
    current_session,
    get_binding_pool,
    get_or_load_snapshot,
    ngfw_client_for,
)
from ..domain import trace_engine
from ..domain.binding_pool import BindingPool
from ..domain.session_store import Session
from ..domain.user_sessions import user_source_addresses
from ..errors import StuckError, validation_error
from ..logging_setup import log_event
from ..ngfw import endpoints as ep
from ..ngfw import schemas as S

_trace_log = logging.getLogger("stuck.trace")

router = APIRouter(prefix="/api", tags=["trace"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TraceRequest(BaseModel):
    url: str = Field(min_length=1)
    user_id: Optional[str] = None
    protocol: Literal["tcp", "udp"] = "tcp"
    dst_port: Optional[int] = Field(default=None, ge=1, le=65535)
    source_ip: Optional[str] = None


def _find_user(snap, user_id: str) -> S.NgfwUser:
    for u in snap.users:
        if str(u.id) == str(user_id):
            return u
    raise StuckError("not_found", "Unknown user_id", details={"user_id": user_id})


@router.post("/trace")
async def trace(
    body: TraceRequest,
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
):
    if not body.url.strip():
        raise validation_error("url is required")

    snap = await get_or_load_snapshot(session, pool)
    user = _find_user(snap, body.user_id) if body.user_id else None

    client = ngfw_client_for(session)
    source_ip: str | None = None
    if body.source_ip:
        try:
            source_ip = str(ipaddress.ip_address(body.source_ip.strip()))
        except ValueError as exc:
            raise validation_error("source_ip must be an IPv4 or IPv6 address") from exc

    if user is not None:
        live_sessions, auth_rules = await asyncio.gather(
            ep.get_auth_sessions(client),
            ep.get_auth_rules(client),
        )
        addresses = user_source_addresses(live_sessions, auth_rules, str(user.id))
        available_ips = {item["ip"] for item in addresses}
        if source_ip is not None and source_ip not in available_ips:
            raise validation_error(
                "source_ip is not active or assigned to the selected user",
                user_id=str(user.id),
                source_ip=source_ip,
            )
        if source_ip is None:
            if len(available_ips) == 1:
                source_ip = next(iter(available_ips))
            elif len(available_ips) > 1:
                raise validation_error(
                    "The selected user has multiple active or assigned source IP addresses; choose one",
                    user_id=str(user.id),
                    source_ips=sorted(available_ips),
                )

    try:
        result = await trace_engine.run_trace(
            snap,
            client,
            url=body.url,
            user=user,
            protocol=body.protocol,
            dst_port_override=body.dst_port,
            source_ip=source_ip,
        )
    except ValueError as exc:
        raise validation_error(f"Invalid url: {exc}") from exc

    # Phase 2.5: log every trace outcome (server, url, user, verdict, rule).
    summary = result["summary"]
    matched_rule = None
    if summary["blocked_at"]:
        blocking = next((s for s in result["stages"] if s["key"] == summary["blocked_at"]), None)
        if blocking:
            matched_rule = (blocking.get("detail") or {}).get("rule_id")
    log_event(
        _trace_log,
        "trace_result",
        server=session.server,
        url=body.url,
        user_id=body.user_id,
        verdict=summary["verdict"],
        blocked_at=summary["blocked_at"],
        rule_id=matched_rule,
    )
    # (v2) top-level: which rules snapshot this trace was computed on.
    result["rules_updated_at"] = _iso(snap.loaded_at)
    return result


@router.post("/rules/refresh")
async def rules_refresh(
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
):
    # (v2.1) Reloads via the ACTIVE session's NGFW cookie; if it has expired on
    # the NGFW side, NgfwClient raises session_expired per contract.
    snap = await get_or_load_snapshot(session, pool, force=True)
    return {
        "ok": True,
        # (v2) renamed from loaded_at.
        "rules_updated_at": _iso(snap.loaded_at),
        "counts": snap.counts(),
    }

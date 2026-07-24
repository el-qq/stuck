"""Access-compare endpoint: POST /api/trace/compare (docs/API_CONTRACT.md).

Two subjects, one target, one snapshot: run both as ordinary read-only traces
and return each side's full result plus a per-stage diff naming the first stage
where the subjects genuinely diverge. Gated by ``STUCK_ENABLE_ACCESS_COMPARE``
exactly like hygiene/snapshots; the binding comes from the session only and the
snapshot load enforces ``access_profile.trace_allowed``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..deps import current_session, get_binding_pool, get_or_load_snapshot, ngfw_client_for
from ..domain.access_compare import run_access_compare
from ..domain.binding_pool import BindingPool
from ..domain.compare_subjects import resolve_compare_subjects
from ..domain.session_store import Session
from ..errors import StuckError, validation_error
from ..logging_setup import log_event

_compare_log = logging.getLogger("stuck.compare")

router = APIRouter(prefix="/api", tags=["compare"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class CompareSubject(BaseModel):
    user_id: str | None = None
    source_ip: str | None = None


class CompareRequest(BaseModel):
    url: str = Field(min_length=1)
    protocol: Literal["any", "ah", "esp", "gre", "icmp", "tcp", "udp", "tcp_udp"] = "any"
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    a: CompareSubject
    b: CompareSubject


@router.post("/trace/compare")
async def trace_compare(
    body: CompareRequest,
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    # Gated: when disabled, behave as a non-existent route (do not disclose it).
    if not settings.STUCK_ENABLE_ACCESS_COMPARE:
        raise StuckError("not_found", "Not found")
    if not body.url.strip():
        raise validation_error("url is required")

    # One snapshot for both sides (NFR-2); the load enforces trace_allowed.
    snap = await get_or_load_snapshot(session, pool)
    client = ngfw_client_for(session)

    # Per-side subject resolution: an invalid/ambiguous side raises
    # compare_side_invalid with details.side rather than failing as a 500.
    subject_a, subject_b = await resolve_compare_subjects(snap, client, body.a, body.b)

    try:
        result = await run_access_compare(
            snap,
            client,
            url=body.url,
            protocol=body.protocol,
            dst_port_override=body.dst_port,
            subject_a=subject_a,
            subject_b=subject_b,
        )
    except ValueError as exc:
        raise validation_error(f"Invalid url: {exc}") from exc

    # Log without secrets and WITHOUT source_ip (personal data): only the side
    # user ids, verdicts and the first divergence.
    log_event(
        _compare_log,
        "access_compare",
        server=session.server,
        url=body.url,
        a_user_id=subject_a.user_id,
        b_user_id=subject_b.user_id,
        a_verdict=result["a"]["summary"]["verdict"],
        b_verdict=result["b"]["summary"]["verdict"],
        primary_divergence=result["primary_divergence"],
        divergence_reason=result["divergence_reason"],
    )

    return {
        # Binding comes from the SESSION only — never from the request (§3.8).
        "binding": {"admin": session.admin_login, "server": session.server},
        "target_input": {"url": body.url, "protocol": body.protocol, "dst_port": body.dst_port},
        "a": result["a"],
        "b": result["b"],
        "categories": result["categories"],
        "stages": result["stages"],
        "primary_divergence": result["primary_divergence"],
        "divergence_reason": result["divergence_reason"],
        "identical_subjects": result["identical_subjects"],
        "rules_updated_at": _iso(snap.loaded_at),
        "generated_at": _iso(datetime.now(tz=UTC).timestamp()),
    }

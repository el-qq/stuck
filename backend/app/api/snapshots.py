"""Rule snapshots and snapshot diff endpoints (docs/API_CONTRACT.md).

Feature analysis and decisions: docs/source/snapshots.md. Pattern follows
``api/hygiene.py``: gated by ``STUCK_ENABLE_RULE_SNAPSHOTS`` (404 when
disabled — the feature is not discoverable), binding EXCLUSIVELY from
``stuck_session`` (§3.8: request params/body can never select another pair),
``require_trace_access`` on every route, structured logs without secrets and
without snapshot contents.

Strictly read-only towards NGFW: creating a snapshot copies in-memory data
(``refresh=true`` reuses the same snapshot loader as export/hygiene), the diff
is a pure function, the import parses an administrator-provided document.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from ..config import Settings, get_settings
from ..deps import binding_for, current_session, get_binding_pool, get_or_load_snapshot
from ..domain.admin_access import require_trace_access
from ..domain.binding_pool import Binding, BindingPool, RulesSnapshot
from ..domain.session_store import Session
from ..domain.snapshots import diff as snapshot_diff
from ..domain.snapshots import importer as snapshot_import
from ..domain.snapshots import store as rule_snapshots
from ..domain.snapshots.store import SnapshotEntry
from ..errors import StuckError, not_found, validation_error
from ..logging_setup import log_event

_snapshots_log = logging.getLogger("stuck.snapshots")

router = APIRouter(prefix="/api", tags=["snapshots"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gate(settings: Settings) -> None:
    # Gated: when disabled, behave as a non-existent route (do not disclose it).
    if not settings.STUCK_ENABLE_RULE_SNAPSHOTS:
        raise StuckError("not_found", "Not found")


def _clean_comment(comment: Any) -> str | None:
    """Trim and bound the optional administrator comment (contract: 400)."""
    if comment is None:
        return None
    if not isinstance(comment, str):
        raise validation_error("comment must be a string")
    comment = comment.strip()
    if len(comment) > rule_snapshots.COMMENT_MAX_LENGTH:
        raise validation_error(
            "comment is too long",
            max_length=rule_snapshots.COMMENT_MAX_LENGTH,
        )
    return comment or None


def _clean_file_name(file_name: Any) -> str | None:
    """Keep only a safe imported-file basename for comparison-side labels.

    The name is user-provided display metadata, not a file-system reference.
    Stripping both path separators prevents a pasted absolute client path from
    entering the in-memory snapshot or any API response. It is intentionally
    never included in structured logs.
    """
    if file_name is None:
        return None
    if not isinstance(file_name, str):
        raise validation_error("file_name must be a string")
    basename = file_name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not basename:
        raise validation_error("file_name must contain a basename")
    if len(basename) > rule_snapshots.FILE_NAME_MAX_LENGTH:
        raise validation_error(
            "file_name is too long",
            max_length=rule_snapshots.FILE_NAME_MAX_LENGTH,
        )
    if not basename.isprintable():
        raise validation_error("file_name must not contain control characters")
    return basename


def _descriptor(entry: SnapshotEntry) -> dict[str, Any]:
    """The list/create response element (развилка f). Never the snapshot body."""
    descriptor: dict[str, Any] = {
        "id": entry.id,
        "created_at": _iso(entry.created_at),
        "rules_updated_at": _iso(entry.rules_updated_at),
        "comment": entry.comment,
        "source": entry.source,
        "counts": entry.counts,
    }
    if entry.source == rule_snapshots.SOURCE_IMPORTED:
        descriptor["exported_at"] = entry.exported_at
        descriptor["server"] = entry.server
        descriptor["foreign_server"] = entry.foreign_server
        if entry.file_name is not None:
            descriptor["file_name"] = entry.file_name
    return descriptor


def _binding_payload(session: Session) -> dict[str, str]:
    # Binding comes from the SESSION only — never from the request (§3.8).
    return {"admin": session.admin_login, "server": session.server}


@router.get("/rules/snapshots")
async def list_snapshots(
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    _gate(settings)
    require_trace_access(session.admin_access)
    binding = binding_for(session, pool)
    return {
        "binding": _binding_payload(session),
        "limit": settings.STUCK_SNAPSHOT_LIMIT_PER_BINDING,
        "snapshots": [_descriptor(entry) for entry in rule_snapshots.list_entries(binding)],
    }


class CreateSnapshotRequest(BaseModel):
    comment: str | None = None
    refresh: bool = False


@router.post("/rules/snapshots")
async def create_snapshot(
    body: CreateSnapshotRequest,
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    _gate(settings)
    require_trace_access(session.admin_access)
    comment = _clean_comment(body.comment)
    binding = binding_for(session, pool)
    # Fail on a full list BEFORE any (potential) NGFW refresh round-trip.
    limit = settings.STUCK_SNAPSHOT_LIMIT_PER_BINDING
    rule_snapshots.ensure_capacity(binding, limit)

    # Lazy load / ?refresh — the exact loader export and hygiene use; this is
    # the only NGFW interaction and it is the existing read-only snapshot pull.
    snap = await get_or_load_snapshot(session, pool, force=body.refresh)
    entry = rule_snapshots.add_entry(binding, rule_snapshots.create_manual(snap, comment), limit)

    log_kwargs = {
        "server": session.server,
        "login": session.admin_login,
        "snapshot_id": entry.id,
        "source": entry.source,
        "refresh": body.refresh,
        "rules_updated_at": _iso(entry.rules_updated_at),
        "total": len(binding.saved_snapshots),
    }
    log_event(_snapshots_log, "snapshot_created", **log_kwargs)
    return {"ok": True, "snapshot": _descriptor(entry)}


@router.delete("/rules/snapshots/{snapshot_id}")
async def delete_snapshot(
    snapshot_id: str,
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    _gate(settings)
    require_trace_access(session.admin_access)
    # An unknown id — including any other pair's id, which is simply absent
    # from THIS binding — is 404; repeated deletion is 404 as well.
    binding = pool.get(session.admin_login, session.server)
    if binding is None or not rule_snapshots.remove_entry(binding, snapshot_id):
        raise not_found("Unknown snapshot id")

    log_event(
        _snapshots_log,
        "snapshot_deleted",
        server=session.server,
        login=session.admin_login,
        snapshot_id=snapshot_id,
        total=len(binding.saved_snapshots),
    )
    return {"ok": True}


@router.post("/rules/snapshots/import")
async def import_snapshot(
    request: Request,
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    _gate(settings)
    require_trace_access(session.admin_access)

    # The size limit applies to the raw body BEFORE parsing (h.4 case 3).
    raw = await request.body()
    snapshot_import.check_size(len(raw))
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        # The wrapped file dominates the body; a truncated paste is 'json'.
        raise StuckError(
            "snapshot_import_invalid",
            "The import body is not valid JSON",
            details={"reason": "json"},
        ) from exc
    if not isinstance(payload, dict) or "export" not in payload:
        raise validation_error("Request body must be an object with an 'export' field")
    comment = _clean_comment(payload.get("comment"))
    file_name = _clean_file_name(payload.get("file_name"))

    document = payload["export"]
    if isinstance(document, str):
        # The client may pass the file body verbatim; parse it here so a
        # truncated copy still maps to reason "json".
        document = snapshot_import.parse_json_document(document)

    binding = binding_for(session, pool)
    limit = settings.STUCK_SNAPSHOT_LIMIT_PER_BINDING
    # Imported snapshots share the manual limit (решение В11).
    rule_snapshots.ensure_capacity(binding, limit)

    # NGFW is never called during an import. The file can not "select" a
    # binding either — foreign servers are only flagged (h.4 case 4).
    imported = snapshot_import.parse_export_document(document, current_server=session.server)
    entry = rule_snapshots.add_entry(
        binding,
        rule_snapshots.create_imported(
            imported.snapshot,
            comment,
            exported_at=imported.exported_at,
            server=imported.server,
            foreign_server=imported.foreign_server,
            file_name=file_name,
        ),
        limit,
    )

    log_event(
        _snapshots_log,
        "snapshot_imported",
        server=session.server,
        login=session.admin_login,
        snapshot_id=entry.id,
        foreign_server=entry.foreign_server,
        rules_updated_at=_iso(entry.rules_updated_at),
        total=len(binding.saved_snapshots),
    )
    return {"ok": True, "snapshot": _descriptor(entry)}


CURRENT_REF = "current"


def _side_meta(entry: SnapshotEntry) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "id": entry.id,
        "created_at": _iso(entry.created_at),
        "rules_updated_at": _iso(entry.rules_updated_at),
        "comment": entry.comment,
        "source": entry.source,
    }
    if entry.source == rule_snapshots.SOURCE_IMPORTED:
        meta["foreign_server"] = entry.foreign_server
        if entry.file_name is not None:
            meta["file_name"] = entry.file_name
    return meta


async def _resolve_side(
    ref: str,
    session: Session,
    pool: BindingPool,
    binding: Binding,
    now: float,
) -> tuple[RulesSnapshot, dict[str, Any], bool]:
    """One diff side: a saved entry id or the literal ``current`` (lazy load)."""
    if ref == CURRENT_REF:
        snap = await get_or_load_snapshot(session, pool)
        meta = {
            "id": CURRENT_REF,
            "created_at": _iso(now),
            "rules_updated_at": _iso(snap.loaded_at),
            "comment": None,
            "source": "current",
        }
        return snap, meta, False
    entry = rule_snapshots.find_entry(binding, ref)
    if entry is None:
        raise not_found("Unknown snapshot id")
    return entry.snapshot, _side_meta(entry), entry.anonymized


@router.get("/rules/snapshots/diff")
async def snapshots_diff(
    a: str = Query(),
    b: str = Query(),
    session: Session = Depends(current_session),
    pool: BindingPool = Depends(get_binding_pool),
    settings: Settings = Depends(get_settings),
):
    _gate(settings)
    require_trace_access(session.admin_access)
    binding = binding_for(session, pool)
    now = datetime.now(tz=UTC).timestamp()

    snap_a, meta_a, anonymized_a = await _resolve_side(a, session, pool, binding, now)
    snap_b, meta_b, anonymized_b = await _resolve_side(b, session, pool, binding, now)

    # Any imported side degrades the comparison honestly: both sides are
    # normalized to the anonymized form and the UI must show a banner (h.2).
    anonymized = anonymized_a or anonymized_b
    result = snapshot_diff.diff_snapshots(snap_a, snap_b, anonymized=anonymized)

    log_event(
        _snapshots_log,
        "snapshot_diff",
        server=session.server,
        login=session.admin_login,
        a=meta_a["id"],
        b=meta_b["id"],
        comparison_mode="anonymized" if anonymized else "full",
        summary=result["summary"],
    )
    return {
        "binding": _binding_payload(session),
        "a": meta_a,
        "b": meta_b,
        "generated_at": _iso(now),
        "comparison_mode": "anonymized" if anonymized else "full",
        **result,
    }

"""Named in-memory rule snapshots per (admin, server) binding.

Feature analysis: docs/source/snapshots.md (decisions В1-В11). v1 stores
snapshots ONLY in process memory, attached to the owning ``Binding`` so they
inherit its exact lifecycle (AGENTS.md invariant 5, unchanged):

- logout keeps the binding and therefore keeps its saved snapshots;
- ``BindingPool.discard`` (role degradation) removes the binding together with
  every saved snapshot of the pair;
- a backend restart clears everything.

A ``SnapshotEntry`` holds a reference to an (effectively immutable)
``RulesSnapshot`` — ``set_snapshot`` always replaces the object wholesale and
nothing mutates it afterwards — plus non-secret metadata. Snapshots contain no
secrets by construction (see ``binding_pool.RulesSnapshot``), so neither do the
entries. Creating a snapshot performs ZERO NGFW calls (invariant 1): it is a
pure in-memory copy of already-loaded data.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from ...errors import StuckError
from ..binding_pool import Binding, RulesSnapshot

SOURCE_MANUAL = "manual"
SOURCE_IMPORTED = "imported"

# Snapshot comments are administrator-entered display strings; the limit keeps
# them list-friendly and bounds memory (docs/source/snapshots.md, развилка b).
COMMENT_MAX_LENGTH = 200
# The browser's File.name is normally a basename already. The API keeps a
# separately bounded basename as imported-only display metadata so UI can show
# where a comparison side came from without retaining a client filesystem path.
FILE_NAME_MAX_LENGTH = 200


@dataclass
class SnapshotEntry:
    """One saved point-in-time snapshot of a binding's rules (no secrets)."""

    id: str
    created_at: float
    comment: str | None
    source: str  # SOURCE_MANUAL | SOURCE_IMPORTED
    # When the rules data was read from NGFW (RulesSnapshot.loaded_at for
    # manual entries; the file's rules_updated_at for imported ones). This is
    # not the same moment as created_at.
    rules_updated_at: float
    counts: dict[str, int]
    snapshot: RulesSnapshot
    # Imported-only metadata (source == "imported"):
    exported_at: str | None = None  # exported_at из файла (ISO, as given)
    server: str | None = None  # binding.server из файла
    foreign_server: bool = False  # file server != current pair's server
    file_name: str | None = None  # safe basename supplied by the import client
    # An imported snapshot came through the anonymized export: display fields
    # are absent and user/group ids are opaque. Any diff involving it must run
    # in the "anonymized" comparison mode.
    anonymized: bool = False


def _new_id() -> str:
    """Opaque entry id, unique within a pair (collision chance negligible)."""
    return secrets.token_urlsafe(8)


def create_manual(snapshot: RulesSnapshot, comment: str | None) -> SnapshotEntry:
    return SnapshotEntry(
        id=_new_id(),
        created_at=time.time(),
        comment=comment,
        source=SOURCE_MANUAL,
        rules_updated_at=snapshot.loaded_at,
        counts=snapshot.counts(),
        snapshot=snapshot,
    )


def create_imported(
    snapshot: RulesSnapshot,
    comment: str | None,
    *,
    exported_at: str,
    server: str,
    foreign_server: bool,
    file_name: str | None = None,
) -> SnapshotEntry:
    return SnapshotEntry(
        id=_new_id(),
        created_at=time.time(),
        comment=comment,
        source=SOURCE_IMPORTED,
        rules_updated_at=snapshot.loaded_at,
        counts=snapshot.counts(),
        snapshot=snapshot,
        exported_at=exported_at,
        server=server,
        foreign_server=foreign_server,
        file_name=file_name,
        anonymized=True,
    )


def ensure_capacity(binding: Binding, limit: int) -> None:
    """Explicit error at the limit — never silent eviction (решение В4).

    Manual and imported snapshots share ONE limit per pair (решение В11).
    """
    if len(binding.saved_snapshots) >= limit:
        raise StuckError(
            "snapshot_limit_reached",
            "The snapshot limit for this pair is reached; delete one first",
            details={"limit": limit},
        )


def add_entry(binding: Binding, entry: SnapshotEntry, limit: int) -> SnapshotEntry:
    ensure_capacity(binding, limit)
    binding.saved_snapshots.append(entry)
    return entry


def list_entries(binding: Binding) -> list[SnapshotEntry]:
    """Entries sorted newest-first (created_at desc, insertion as tiebreak)."""
    indexed = list(enumerate(binding.saved_snapshots))
    indexed.sort(key=lambda pair: (-pair[1].created_at, -pair[0]))
    return [entry for _, entry in indexed]


def find_entry(binding: Binding, entry_id: str) -> SnapshotEntry | None:
    for entry in binding.saved_snapshots:
        if entry.id == entry_id:
            return entry
    return None


def remove_entry(binding: Binding, entry_id: str) -> bool:
    entries = binding.saved_snapshots
    for index, entry in enumerate(entries):
        if entry.id == entry_id:
            del entries[index]
            return True
    return False

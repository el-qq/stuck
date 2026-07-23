"""Snapshot anonymization — the single source of truth (docs/source/snapshots.md h.2).

Used by the rules export (GET /api/rules/export) and by the snapshot diff in
its "anonymized" comparison mode, so both features strip exactly the same
display data and replace user/group ids identically. Behavior is unchanged
from the original ``app/api/export.py`` helpers it was extracted from.
"""

from __future__ import annotations

from typing import Any

from .binding_pool import RulesSnapshot

# These fields are useful in the product UI, but are neither needed to replay
# the rules nor appropriate for a diagnostic attachment shared outside the
# installation. ``title`` and ``domain_name`` are included because aliases and
# directory domains can reveal the same personal information under other keys.
ANONYMIZED_FIELDS = frozenset({"comment", "description", "domain_name", "login", "name", "title"})


def identity_map(snap: RulesSnapshot) -> dict[str, str]:
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


def anonymize(value: Any, replacements: dict[str, str]) -> Any:
    """Remove display data recursively and replace known user/group IDs."""
    if isinstance(value, dict):
        return {key: anonymize(item, replacements) for key, item in value.items() if key not in ANONYMIZED_FIELDS}
    if isinstance(value, list):
        return [anonymize(item, replacements) for item in value]
    if isinstance(value, str):
        return replacements.get(value, value)
    return value

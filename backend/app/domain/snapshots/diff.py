"""Snapshot diff engine (docs/source/snapshots.md, развилки c/f, решения В5/В8/В9).

``diff_snapshots(a, b, anonymized=...)`` is a pure, deterministic function of
two ``RulesSnapshot`` objects. It never calls NGFW and its result is computed
on demand, never stored.

Coverage (решение В5):
- level 1 — every ordered rule table (first-match order is significant);
- level 2 — module states / scalar settings (``states``);
- level 3 — objects: ``aliases`` values, structural ``users`` fields and the
  network context used by the trace engine (local DNS zones, LAN networks and
  NGFW interface addresses).

Change kinds per ordered table, matched by rule ``id``:
- ``added``   — id only in B;
- ``removed`` — id only in A;
- ``changed`` — id in both, normalized content differs (``changed_fields``
  lists per-field from/to; display fields included in full mode — решение В8);
- ``moved``   — id in both, content equivalent, but the RELATIVE position
  changed. Computed via the longest common subsequence of ids (as the longest
  increasing subsequence of B-positions taken in A-order), NOT via absolute
  indexes — inserting one rule at the top must not cascade into "everything
  moved". A rule both changed and repositioned stays a single ``changed``
  entry with both positions.

Normalization uses ``model_dump(include=model_fields)`` so vendor extras never
produce noise (развилка b). In ``anonymized`` mode (any imported side) both
sides are passed through ``domain.anonymize`` — display fields are excluded
from comparison and user/group ids collapse to the same positional ``user-N``
labels the export uses (развилка h.2).
"""

from __future__ import annotations

from bisect import bisect_left
from typing import Any, Callable

from pydantic import BaseModel

from ..anonymize import anonymize, identity_map
from ..binding_pool import RulesSnapshot

# (public table key, RulesSnapshot attribute) — the fixed level-1 order.
ORDERED_TABLES: tuple[tuple[str, str], ...] = (
    ("fw_pre_filter", "fw_pre_filter"),
    ("fw_forward", "fw_forward"),
    ("fw_input", "fw_input"),
    ("fw_dnat", "fw_dnat"),
    ("fw_snat", "fw_snat"),
    ("hw_mac", "hw_rules_mac"),
    ("hw_src_ip", "hw_rules_src_ip"),
    ("hw_dst_ip", "hw_rules_dst_ip"),
    ("hw_src_dst_ip", "hw_rules_src_dst_ip"),
    ("cf_rules", "cf_rules"),
    ("shaper_rules", "shaper_rules"),
    ("ips_bypass", "ips_bypass"),
)

_HW_TABLES = frozenset({"hw_mac", "hw_src_ip", "hw_dst_ip", "hw_src_dst_ip"})

# These collections influence trace evaluation but are not first-match rule
# chains. Their transport order is irrelevant, so they must never report a
# misleading ``moved`` entry merely because NGFW returned the same objects in a
# different order. The count shown for a saved snapshot includes all three.
_UNORDERED_MODEL_TABLES: tuple[tuple[str, str], ...] = (
    ("aliases", "aliases"),
    ("dns_zones", "dns_zones"),
)
_UNORDERED_STRING_TABLES: tuple[tuple[str, str], ...] = (
    ("lan_networks", "lan_networks"),
    ("ngfw_addresses", "ngfw_addresses"),
)

# Level-3 users diff compares ONLY structural fields (решение В5): display
# fields of users are never diffed, in any mode.
_USER_STRUCTURAL_FIELDS = ("id", "enabled", "parent_id")

# Level-2 scalar states: (key, reader). Keys form an open vocabulary for the
# frontend (like reason_key) — new entries may appear without a contract bump.
_STATE_READERS: tuple[tuple[str, Callable[[RulesSnapshot], Any]], ...] = (
    ("fw_state.enabled", lambda s: s.fw_state.enabled),
    ("cf_state.enabled", lambda s: s.cf_state.enabled),
    ("ips_state.enabled", lambda s: s.ips_state.enabled),
    ("shaper_state.enabled", lambda s: s.shaper_state.enabled),
    ("av_enabled", lambda s: s.av_enabled),
    ("fw_settings.automatic_snat_enabled", lambda s: s.fw_settings.automatic_snat_enabled),
    ("hw_settings.mode", lambda s: s.hw_settings.mode if s.hw_settings is not None else None),
)


def _dump(model: BaseModel) -> dict[str, Any]:
    """Known-schema fields only — vendor extras must not cause false 'changed'."""
    return model.model_dump(mode="json", include=set(type(model).model_fields))


def _lcs_id_set(order_a: list[str], order_b: list[str]) -> set[str]:
    """Ids forming a longest common subsequence of the two orders.

    Both lists contain the same set of unique ids, so the LCS equals the
    longest increasing subsequence of B-positions visited in A-order
    (O(n log n) patience algorithm with reconstruction).
    """
    pos_b = {id_: i for i, id_ in enumerate(order_b)}
    seq = [pos_b[id_] for id_ in order_a]

    tails: list[int] = []  # tails[k] = smallest ending value of an IS of length k+1
    tail_index: list[int] = []  # index in seq of that ending value
    prev: list[int] = [-1] * len(seq)
    for i, value in enumerate(seq):
        k = bisect_left(tails, value)
        if k == len(tails):
            tails.append(value)
            tail_index.append(i)
        else:
            tails[k] = value
            tail_index[k] = i
        prev[i] = tail_index[k - 1] if k > 0 else -1

    ids: set[str] = set()
    i = tail_index[-1] if tail_index else -1
    while i != -1:
        ids.add(order_a[i])
        i = prev[i]
    return ids


def _changed_fields(norm_a: dict[str, Any], norm_b: dict[str, Any]) -> list[dict[str, Any]]:
    fields = []
    for key in sorted(set(norm_a) | set(norm_b)):
        from_value = norm_a.get(key)
        to_value = norm_b.get(key)
        if from_value != to_value:
            fields.append({"field": key, "from": from_value, "to": to_value})
    return fields


def _display_name(norm: dict[str, Any]) -> str | None:
    """UI display name from the normalized entry (session response, not export).

    In anonymized mode both names are already stripped by ``anonymize`` — the
    result is then None by construction, never a leak.
    """
    for key in ("name", "title"):
        value = norm.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _diff_ordered(
    norms_a: list[dict[str, Any]],
    norms_b: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Diff two normalized, ordered entry lists (each entry has a string 'id')."""
    ids_a = [str(norm.get("id")) for norm in norms_a]
    ids_b = [str(norm.get("id")) for norm in norms_b]
    index_a = {id_: i for i, id_ in enumerate(ids_a)}
    index_b = {id_: i for i, id_ in enumerate(ids_b)}

    common_order_a = [id_ for id_ in ids_a if id_ in index_b]
    common_order_b = [id_ for id_ in ids_b if id_ in index_a]
    stable_ids = _lcs_id_set(common_order_a, common_order_b)

    entries: list[dict[str, Any]] = []

    for id_ in ids_a:
        if id_ not in index_b:
            norm = norms_a[index_a[id_]]
            entries.append(
                {
                    "kind": "removed",
                    "id": id_,
                    "name": _display_name(norm),
                    "position_a": index_a[id_] + 1,
                    "position_b": None,
                }
            )
    for id_ in ids_b:
        norm_b = norms_b[index_b[id_]]
        if id_ not in index_a:
            entries.append(
                {
                    "kind": "added",
                    "id": id_,
                    "name": _display_name(norm_b),
                    "position_a": None,
                    "position_b": index_b[id_] + 1,
                }
            )
            continue
        norm_a = norms_a[index_a[id_]]
        if norm_a != norm_b:
            entries.append(
                {
                    "kind": "changed",
                    "id": id_,
                    "name": _display_name(norm_b),
                    "position_a": index_a[id_] + 1,
                    "position_b": index_b[id_] + 1,
                    "changed_fields": _changed_fields(norm_a, norm_b),
                }
            )
        elif id_ not in stable_ids:
            entries.append(
                {
                    "kind": "moved",
                    "id": id_,
                    "name": _display_name(norm_b),
                    "position_a": index_a[id_] + 1,
                    "position_b": index_b[id_] + 1,
                }
            )

    entries.sort(
        key=lambda e: (
            e["position_b"] if e["position_b"] is not None else float("inf"),
            e["position_a"] if e["position_a"] is not None else float("inf"),
        )
    )
    return entries


def _diff_unordered(
    norms_a: list[dict[str, Any]],
    norms_b: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Diff id-keyed objects whose order has no semantic meaning.

    ``aliases``, users and network context are maps/sets from the trace
    engine's point of view. Reporting a movement for them would imply a policy
    order that does not exist, so this variant deliberately emits only added,
    removed and changed entries. Positions are always ``None`` for the same
    reason.
    """
    by_id_a = {str(norm.get("id")): norm for norm in norms_a}
    by_id_b = {str(norm.get("id")): norm for norm in norms_b}
    entries: list[dict[str, Any]] = []

    for id_ in sorted(set(by_id_a) - set(by_id_b)):
        norm = by_id_a[id_]
        entries.append(
            {
                "kind": "removed",
                "id": id_,
                "name": _display_name(norm),
                "position_a": None,
                "position_b": None,
            }
        )
    for id_ in sorted(set(by_id_b) - set(by_id_a)):
        norm = by_id_b[id_]
        entries.append(
            {
                "kind": "added",
                "id": id_,
                "name": _display_name(norm),
                "position_a": None,
                "position_b": None,
            }
        )
    for id_ in sorted(set(by_id_a) & set(by_id_b)):
        norm_a = by_id_a[id_]
        norm_b = by_id_b[id_]
        if norm_a != norm_b:
            entries.append(
                {
                    "kind": "changed",
                    "id": id_,
                    "name": _display_name(norm_b),
                    "position_a": None,
                    "position_b": None,
                    "changed_fields": _changed_fields(norm_a, norm_b),
                }
            )
    return entries


def _normalize_models(
    models: list[BaseModel],
    replacements: dict[str, str] | None,
) -> list[dict[str, Any]]:
    norms = [_dump(model) for model in models]
    if replacements is not None:
        norms = [anonymize(norm, replacements) for norm in norms]
    return norms


def _normalize_users(snap: RulesSnapshot, replacements: dict[str, str] | None) -> list[dict[str, Any]]:
    norms = []
    for user in snap.users:
        norm: dict[str, Any] = {key: getattr(user, key) for key in _USER_STRUCTURAL_FIELDS}
        if replacements is not None:
            norm = anonymize(norm, replacements)
        norms.append(norm)
    return norms


def _normalize_strings(values: list[str], replacements: dict[str, str] | None) -> list[dict[str, Any]]:
    """Give an unordered string set the same id-keyed shape as objects.

    LAN networks and NGFW addresses are membership collections. Sorting and
    de-duplicating here makes the diff immune to harmless response ordering or
    duplicate rows while still reporting every added or removed value.
    """
    norms = [{"id": value} for value in sorted(set(values))]
    if replacements is not None:
        norms = [anonymize(norm, replacements) for norm in norms]
    return norms


def _append_entries(
    tables: list[dict[str, Any]],
    summary: dict[str, int],
    table: str,
    entries: list[dict[str, Any]],
) -> None:
    """Store one non-empty table and account for its public summary kinds."""
    if not entries:
        return
    tables.append({"table": table, "entries": entries})
    for entry in entries:
        summary[entry["kind"]] += 1


def diff_snapshots(a: RulesSnapshot, b: RulesSnapshot, *, anonymized: bool) -> dict[str, Any]:
    """Structured diff of two snapshots: {summary, tables, states}.

    Direction convention: A is "before", B is "after"; ``added`` = present in
    B only. The caller decides which side is which — comparing backwards is
    legal (развилка d).
    """
    repl_a = identity_map(a) if anonymized else None
    repl_b = identity_map(b) if anonymized else None

    # An hw_settings missing on either side means the feature is not exposed
    # there — the hardware tables are incomparable and must NOT be reported as
    # a mass add/remove (развилка h.3). The mode difference (or None) still
    # surfaces through the "hw_settings.mode" state entry below.
    hw_comparable = a.hw_settings is not None and b.hw_settings is not None

    tables: list[dict[str, Any]] = []
    summary = {"added": 0, "removed": 0, "changed": 0, "moved": 0}

    for table_key, attr in ORDERED_TABLES:
        if table_key in _HW_TABLES and not hw_comparable:
            continue
        entries = _diff_ordered(
            _normalize_models(getattr(a, attr), repl_a),
            _normalize_models(getattr(b, attr), repl_b),
        )
        _append_entries(tables, summary, table_key, entries)

    # Level 3: these are objects/sets, not ordered policies. Alias values and
    # network context can alter a trace result even when no rule changed.
    for table_key, attr in _UNORDERED_MODEL_TABLES:
        models_a = list(a.aliases.values()) if attr == "aliases" else getattr(a, attr)
        models_b = list(b.aliases.values()) if attr == "aliases" else getattr(b, attr)
        _append_entries(
            tables,
            summary,
            table_key,
            _diff_unordered(_normalize_models(models_a, repl_a), _normalize_models(models_b, repl_b)),
        )

    _append_entries(
        tables,
        summary,
        "users",
        _diff_unordered(_normalize_users(a, repl_a), _normalize_users(b, repl_b)),
    )

    for table_key, attr in _UNORDERED_STRING_TABLES:
        _append_entries(
            tables,
            summary,
            table_key,
            _diff_unordered(
                _normalize_strings(getattr(a, attr), repl_a),
                _normalize_strings(getattr(b, attr), repl_b),
            ),
        )

    states: list[dict[str, Any]] = []
    for key, read in _STATE_READERS:
        from_value = read(a)
        to_value = read(b)
        if from_value != to_value:
            states.append({"key": key, "from": from_value, "to": to_value})

    return {
        "summary": {
            **summary,
            "states_changed": len(states),
            "tables_changed": len(tables),
        },
        "tables": tables,
        "states": states,
    }

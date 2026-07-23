"""Tests for the in-memory rule-snapshot store (app/domain/snapshots/store.py).

Phase 1 of docs/source/snapshots.md: entries live on the owning Binding, so
they inherit its lifecycle — pool.discard removes them with the pair, logout
keeps them, a fresh pool (restart) has none. The per-pair limit is explicit
(snapshot_limit_reached), never a silent eviction.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.domain.binding_pool import BindingPool, RulesSnapshot
from app.domain.snapshots import store as rule_snapshots
from app.errors import StuckError
from app.ngfw import schemas as S


def _snap(loaded_at: float = 1000.0) -> RulesSnapshot:
    return RulesSnapshot(
        users=[],
        aliases={},
        fw_forward=[],
        fw_input=[],
        fw_state=S.StateFlag(enabled=True),
        cf_state=S.StateFlag(),
        cf_rules=[],
        cf_categories=None,
        ips_state=S.StateFlag(),
        ips_bypass=[],
        av_enabled=False,
        loaded_at=loaded_at,
    )


class TestSnapshotStore:
    def test_create_manual_metadata(self):
        snap = _snap(loaded_at=1234.0)
        entry = rule_snapshots.create_manual(snap, "before change")

        assert entry.source == "manual"
        assert entry.comment == "before change"
        assert entry.rules_updated_at == 1234.0
        assert entry.counts == snap.counts()
        assert entry.snapshot is snap  # reference, not a lossy copy
        assert entry.anonymized is False
        assert isinstance(entry.id, str) and entry.id

    def test_ids_are_unique(self):
        snap = _snap()
        ids = {rule_snapshots.create_manual(snap, None).id for _ in range(50)}
        assert len(ids) == 50

    def test_add_list_find_remove(self):
        pool = BindingPool()
        binding, _ = pool.ensure("admin", "srv")
        e1 = rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), "a"), limit=10)
        e2 = rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), "b"), limit=10)

        listed = rule_snapshots.list_entries(binding)
        assert [e.id for e in listed] == [e2.id, e1.id]  # newest first
        assert rule_snapshots.find_entry(binding, e1.id) is e1
        assert rule_snapshots.find_entry(binding, "no-such-id") is None
        assert rule_snapshots.remove_entry(binding, e1.id) is True
        assert rule_snapshots.remove_entry(binding, e1.id) is False  # idempotent 404 at API level
        assert [e.id for e in rule_snapshots.list_entries(binding)] == [e2.id]

    def test_limit_is_explicit_error_never_eviction(self):
        pool = BindingPool()
        binding, _ = pool.ensure("admin", "srv")
        first = rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), "1"), limit=2)
        rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), "2"), limit=2)

        with pytest.raises(StuckError) as exc:
            rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), "3"), limit=2)
        assert exc.value.code == "snapshot_limit_reached"
        assert exc.value.http_status == 409
        assert exc.value.details == {"limit": 2}
        # The oldest entry was NOT silently evicted.
        assert rule_snapshots.find_entry(binding, first.id) is first
        assert len(binding.saved_snapshots) == 2

    def test_imported_counts_against_the_same_limit(self):
        pool = BindingPool()
        binding, _ = pool.ensure("admin", "srv")
        rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), None), limit=1)
        imported = rule_snapshots.create_imported(
            _snap(),
            None,
            exported_at="2026-07-23T00:00:00Z",
            server="srv",
            foreign_server=False,
            file_name="rules.json",
        )
        with pytest.raises(StuckError) as exc:
            rule_snapshots.add_entry(binding, imported, limit=1)
        assert exc.value.code == "snapshot_limit_reached"

    def test_imported_entry_metadata(self):
        entry = rule_snapshots.create_imported(
            _snap(loaded_at=555.0),
            "from prod",
            exported_at="2026-07-23T00:00:00Z",
            server="10.0.0.9",
            foreign_server=True,
            file_name="production-rules.json",
        )
        assert entry.source == "imported"
        assert entry.anonymized is True
        assert entry.exported_at == "2026-07-23T00:00:00Z"
        assert entry.server == "10.0.0.9"
        assert entry.foreign_server is True
        assert entry.rules_updated_at == 555.0
        assert entry.file_name == "production-rules.json"


class TestSnapshotLifecycle:
    def test_pairs_are_isolated(self):
        pool = BindingPool()
        binding_a, _ = pool.ensure("adminA", "srv")
        binding_b, _ = pool.ensure("adminB", "srv")
        entry = rule_snapshots.add_entry(binding_a, rule_snapshots.create_manual(_snap(), None), limit=10)

        assert rule_snapshots.find_entry(binding_b, entry.id) is None
        assert rule_snapshots.list_entries(binding_b) == []

    def test_discard_removes_snapshots_with_the_pair(self):
        pool = BindingPool()
        binding, _ = pool.ensure("admin", "srv")
        rule_snapshots.add_entry(binding, rule_snapshots.create_manual(_snap(), None), limit=10)

        pool.discard("admin", "srv")
        assert pool.get("admin", "srv") is None
        # A re-created binding starts empty — the old list is not resurrected.
        fresh, created = pool.ensure("admin", "srv")
        assert created is True
        assert rule_snapshots.list_entries(fresh) == []

    def test_snapshots_survive_snapshot_refresh(self):
        """set_snapshot replaces only the live snapshot, never the saved ones."""
        pool = BindingPool()
        binding, _ = pool.ensure("admin", "srv")
        old = _snap(loaded_at=1.0)
        pool.set_snapshot(binding, old)
        entry = rule_snapshots.add_entry(binding, rule_snapshots.create_manual(old, None), limit=10)

        pool.set_snapshot(binding, _snap(loaded_at=2.0))
        assert rule_snapshots.find_entry(binding, entry.id).snapshot is old


class TestSnapshotConfig:
    def test_defaults(self):
        settings = Settings(STUCK_ALLOW_ANY_NGFW=True)
        assert settings.STUCK_ENABLE_RULE_SNAPSHOTS is True
        assert settings.STUCK_SNAPSHOT_LIMIT_PER_BINDING == 10

    @pytest.mark.parametrize("value", [0, -1, 51])
    def test_limit_range_is_validated(self, value):
        with pytest.raises(ValidationError):
            Settings(STUCK_ALLOW_ANY_NGFW=True, STUCK_SNAPSHOT_LIMIT_PER_BINDING=value)

    @pytest.mark.parametrize("value", [1, 50])
    def test_limit_bounds_accepted(self, value):
        settings = Settings(STUCK_ALLOW_ANY_NGFW=True, STUCK_SNAPSHOT_LIMIT_PER_BINDING=value)
        assert settings.STUCK_SNAPSHOT_LIMIT_PER_BINDING == value

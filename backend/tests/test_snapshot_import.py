"""Tests for the stuck.rules/v2 import parser (app/domain/snapshots/importer.py).

Covers the edge cases of docs/source/snapshots.md h.4 at the domain level (the
HTTP-layer cases — limit, duplicates, error envelopes — live in
tests/test_snapshots_api.py) and the key comparability invariant: exporting a
snapshot and importing it back yields an empty anonymized diff against itself.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from app.api.export import RULES_EXPORT_FORMAT, _build_snapshot
from app.domain.snapshots import diff as snapshot_diff
from app.domain.snapshots import importer as snapshot_import
from app.domain.anonymize import anonymize, identity_map
from app.domain.binding_pool import RulesSnapshot
from app.errors import StuckError
from app.ngfw import schemas as S

SERVER = "192.168.1.1"


def _snap(**kw) -> RulesSnapshot:
    defaults = dict(
        users=[S.NgfwUser(id="user.id.1", name="John", login="john", parent_id="group.id.1")],
        aliases={"al1": S.Alias(id="al1", type="ip_list", title="Office", values=["10.0.0.0/24"])},
        fw_forward=[S.FirewallRule(id="fw1", action="drop", comment="note")],
        fw_input=[],
        fw_state=S.StateFlag(enabled=True),
        cf_state=S.StateFlag(enabled=True),
        cf_rules=[S.ContentFilterRule(id="3", access="deny", aliases=["user.id.1"])],
        cf_categories=["cat.a"],
        ips_state=S.StateFlag(),
        ips_bypass=[],
        av_enabled=True,
        hw_settings=S.HwFilterSettings(mode="src-ip"),
        loaded_at=1_700_000_000.0,
    )
    defaults.update(kw)
    return RulesSnapshot(**defaults)


def _export_doc(snap: RulesSnapshot, *, server: str = SERVER) -> dict:
    """The exact document GET /api/rules/export builds (anonymized)."""
    replacements = identity_map(snap)
    return {
        "format": RULES_EXPORT_FORMAT,
        "exported_at": "2026-07-23T10:00:00Z",
        "rules_updated_at": "2026-07-23T09:00:00Z",
        "binding": {"server": server},
        "filtered_by_user_id": None,
        "snapshot": anonymize(_build_snapshot(snap, None, None), replacements),
    }


class TestEnvelopeValidation:
    def test_invalid_json_text(self):
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_json_document('{"format": "stuck.rules/v2", "snap')  # truncated paste
        assert exc.value.code == "snapshot_import_invalid"
        assert exc.value.details == {"reason": "json"}

    @pytest.mark.parametrize("doc", [None, 42, [], "text", {"hello": 1}, {"snapshot": {}}])
    def test_foreign_document_is_structure_error(self, doc):
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.code == "snapshot_import_invalid"
        assert exc.value.details == {"reason": "structure"}

    @pytest.mark.parametrize("fmt", ["stuck.rules/v1", "stuck.rules/v3", "vendor.backup/v9"])
    def test_other_versions_unsupported(self, fmt):
        doc = _export_doc(_snap())
        doc["format"] = fmt
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.code == "snapshot_import_unsupported_format"
        assert exc.value.details == {"format": fmt}

    def test_non_string_format_detail_is_null(self):
        doc = _export_doc(_snap())
        doc["format"] = 2
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.code == "snapshot_import_unsupported_format"
        assert exc.value.details == {"format": None}

    def test_size_limit_checked_before_parsing(self):
        with pytest.raises(StuckError) as exc:
            snapshot_import.check_size(snapshot_import.IMPORT_MAX_BYTES + 1)
        assert exc.value.code == "snapshot_import_too_large"
        assert exc.value.http_status == 413
        assert exc.value.details == {"limit_bytes": snapshot_import.IMPORT_MAX_BYTES}
        snapshot_import.check_size(snapshot_import.IMPORT_MAX_BYTES)  # boundary passes

    def test_filtered_export_rejected(self):
        doc = _export_doc(_snap())
        doc["filtered_by_user_id"] = "user-1"
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.details == {"reason": "filtered_export"}

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d.pop("binding"),
            lambda d: d.__setitem__("binding", {"server": ""}),
            lambda d: d.__setitem__("binding", "srv"),
            lambda d: d.pop("rules_updated_at"),
            lambda d: d.__setitem__("rules_updated_at", "not-a-date"),
            lambda d: d.pop("exported_at"),
            lambda d: d.__setitem__("snapshot", []),
        ],
        ids=[
            "no-binding",
            "empty-server",
            "binding-not-dict",
            "no-updated-at",
            "bad-date",
            "no-exported-at",
            "snapshot-not-dict",
        ],
    )
    def test_broken_envelope_fields(self, mutate):
        doc = _export_doc(_snap())
        mutate(doc)
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.code == "snapshot_import_invalid"
        assert exc.value.details == {"reason": "structure"}

    def test_overlong_string_rejected(self):
        doc = _export_doc(_snap())
        doc["snapshot"]["lan_networks"] = ["a" * (snapshot_import.MAX_STRING_LENGTH + 1)]
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.details == {"reason": "field_too_long"}

    def test_wrong_element_types_rejected(self):
        doc = _export_doc(_snap())
        doc["snapshot"]["firewall_forward"] = [{"id": ["not", "a", "string"]}]
        with pytest.raises(StuckError) as exc:
            snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert exc.value.details == {"reason": "structure"}

    def test_unknown_element_fields_tolerated(self):
        doc = _export_doc(_snap())
        doc["snapshot"]["firewall_forward"][0]["future_vendor_field"] = "x"
        imported = snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert imported.snapshot.fw_forward[0].id == "fw1"


class TestParsedSnapshot:
    def test_happy_path_metadata(self):
        imported = snapshot_import.parse_export_document(_export_doc(_snap()), current_server=SERVER)
        assert imported.exported_at == "2026-07-23T10:00:00Z"
        assert imported.server == SERVER
        assert imported.foreign_server is False
        # loaded_at reflects when NGFW data was read, per the file.
        expected = datetime(2026, 7, 23, 9, 0, 0, tzinfo=timezone.utc).timestamp()
        assert imported.snapshot.loaded_at == pytest.approx(expected)

    def test_foreign_server_is_flagged_not_rejected(self):
        imported = snapshot_import.parse_export_document(_export_doc(_snap(), server="10.9.9.9"), current_server=SERVER)
        assert imported.foreign_server is True
        assert imported.server == "10.9.9.9"

    def test_missing_optional_sections_default(self):
        """An older v2 without hardware/speed_limit sections still imports."""
        doc = _export_doc(_snap())
        for key in ("hardware", "speed_limit", "dns_zones", "ngfw_addresses", "firewall_pre_filter"):
            doc["snapshot"].pop(key, None)
        imported = snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert imported.snapshot.hw_settings is None
        assert imported.snapshot.shaper_rules == []
        assert imported.snapshot.dns_zones == []

    def test_null_hardware_settings_means_feature_absent(self):
        doc = _export_doc(_snap(hw_settings=None))
        assert doc["snapshot"]["hardware"]["settings"] is None
        imported = snapshot_import.parse_export_document(doc, current_server=SERVER)
        assert imported.snapshot.hw_settings is None

    def test_empty_tables_are_valid(self):
        empty = _snap(
            users=[],
            aliases={},
            fw_forward=[],
            cf_rules=[],
            cf_categories=[],
        )
        imported = snapshot_import.parse_export_document(_export_doc(empty), current_server=SERVER)
        assert imported.snapshot.users == []
        assert imported.snapshot.fw_forward == []


class TestRoundTrip:
    def test_export_import_diff_with_itself_is_empty(self):
        """Key comparability invariant (план, фаза 3): a live snapshot diffed in
        anonymized mode against its own imported export shows no changes."""
        snap = _snap(loaded_at=time.time())
        imported = snapshot_import.parse_export_document(_export_doc(snap), current_server=SERVER)

        result = snapshot_diff.diff_snapshots(snap, imported.snapshot, anonymized=True)
        assert result["tables"] == []
        assert result["states"] == []
        assert result["summary"]["added"] == 0
        assert result["summary"]["removed"] == 0
        assert result["summary"]["changed"] == 0
        assert result["summary"]["moved"] == 0

    def test_full_mode_against_import_would_be_noisy(self):
        """Sanity check of WHY anonymized mode exists: the same pair in full
        mode reports display-field noise (stripped name/comment/title)."""
        snap = _snap()
        imported = snapshot_import.parse_export_document(_export_doc(snap), current_server=SERVER)
        result = snapshot_diff.diff_snapshots(snap, imported.snapshot, anonymized=False)
        assert result["tables"] != []

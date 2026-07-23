"""Tests for the snapshot diff engine (app/domain/snapshots/diff.py).

Pure-function tests over minimal RulesSnapshot pairs (docs/source/snapshots.md,
развилка c): added/removed/changed/moved semantics, LCS-based moved detection
(no cascade from a single insertion), module states, aliases/users coverage and
the anonymized comparison mode.
"""

from __future__ import annotations

from app.domain.snapshots import diff as snapshot_diff
from app.domain.binding_pool import RulesSnapshot
from app.ngfw import schemas as S


def _rule(rid, *, action="accept", enabled=True, comment="", name=None, sources=None) -> S.FirewallRule:
    blocks = [S.SourceDest(addresses=list(sources))] if sources is not None else []
    extra = {"name": name} if name is not None else {}
    return S.FirewallRule(id=str(rid), action=action, enabled=enabled, comment=comment, sources=blocks, **extra)


def _snap(
    fw_forward=None,
    *,
    users=None,
    aliases=None,
    cf_state=False,
    cf_rules=None,
    **kw,
) -> RulesSnapshot:
    return RulesSnapshot(
        users=list(users or []),
        aliases=dict(aliases or {}),
        fw_forward=list(fw_forward or []),
        fw_input=[],
        fw_state=S.StateFlag(enabled=True),
        cf_state=S.StateFlag(enabled=cf_state),
        cf_rules=list(cf_rules or []),
        cf_categories=None,
        ips_state=S.StateFlag(),
        ips_bypass=[],
        av_enabled=False,
        hw_settings=kw.pop("hw_settings", S.HwFilterSettings(mode="src-ip")),
        **kw,
    )


def _table(result, key):
    for table in result["tables"]:
        if table["table"] == key:
            return table["entries"]
    return []


class TestKinds:
    def test_identical_snapshots_empty_diff(self):
        rules = [_rule(1), _rule(2)]
        result = snapshot_diff.diff_snapshots(_snap(rules), _snap(list(rules)), anonymized=False)
        assert result["tables"] == []
        assert result["states"] == []
        assert result["summary"] == {
            "added": 0,
            "removed": 0,
            "changed": 0,
            "moved": 0,
            "states_changed": 0,
            "tables_changed": 0,
        }

    def test_added_and_removed(self):
        a = _snap([_rule(1), _rule(2)])
        b = _snap([_rule(2), _rule(3)])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        entries = _table(result, "fw_forward")
        kinds = {e["id"]: e["kind"] for e in entries}
        assert kinds == {"1": "removed", "3": "added"}
        removed = next(e for e in entries if e["kind"] == "removed")
        assert removed["position_a"] == 1 and removed["position_b"] is None
        added = next(e for e in entries if e["kind"] == "added")
        assert added["position_a"] is None and added["position_b"] == 2
        assert result["summary"]["added"] == 1 and result["summary"]["removed"] == 1

    def test_changed_lists_fields_with_from_to(self):
        a = _snap([_rule(1, enabled=True, comment="old note")])
        b = _snap([_rule(1, enabled=False, comment="new note")])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        (entry,) = _table(result, "fw_forward")
        assert entry["kind"] == "changed"
        by_field = {f["field"]: f for f in entry["changed_fields"]}
        assert by_field["enabled"] == {"field": "enabled", "from": True, "to": False}
        # Display fields ARE compared in full mode (решение В8).
        assert by_field["comment"] == {"field": "comment", "from": "old note", "to": "new note"}

    def test_swap_block_above_allow_is_moved(self):
        allow = _rule(1, action="accept", sources=["10.0.0.0/8"])
        block = _rule(2, action="drop", sources=["10.0.0.0/8"])
        result = snapshot_diff.diff_snapshots(_snap([allow, block]), _snap([block, allow]), anonymized=False)
        entries = _table(result, "fw_forward")
        # The minimal explanation of a swap is ONE rule moving past the other
        # (LCS keeps the longest stable chain), so exactly one moved entry.
        assert [e["kind"] for e in entries] == ["moved"]
        assert result["summary"]["moved"] == 1
        assert entries[0]["position_a"] != entries[0]["position_b"]

    def test_insertion_at_top_does_not_cascade_moved(self):
        tail = [_rule(i) for i in range(1, 6)]
        result = snapshot_diff.diff_snapshots(_snap(tail), _snap([_rule(99)] + tail), anonymized=False)
        entries = _table(result, "fw_forward")
        assert [e["kind"] for e in entries] == ["added"]
        assert entries[0]["id"] == "99"
        assert result["summary"]["moved"] == 0

    def test_changed_and_repositioned_is_single_changed_entry(self):
        a = _snap([_rule(1), _rule(2), _rule(3)])
        b = _snap([_rule(2), _rule(3), _rule(1, enabled=False)])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        entries = [e for e in _table(result, "fw_forward") if e["id"] == "1"]
        assert len(entries) == 1
        assert entries[0]["kind"] == "changed"
        assert entries[0]["position_a"] == 1
        assert entries[0]["position_b"] == 3

    def test_vendor_extras_do_not_produce_changed(self):
        plain = S.FirewallRule(id="1")
        with_extra = S.FirewallRule.model_validate({"id": "1", "brand_new_vendor_field": "x"})
        result = snapshot_diff.diff_snapshots(_snap([plain]), _snap([with_extra]), anonymized=False)
        assert result["tables"] == []


class TestStatesAndObjects:
    def test_cf_state_toggle_lands_in_states(self):
        result = snapshot_diff.diff_snapshots(_snap(cf_state=True), _snap(cf_state=False), anonymized=False)
        assert {"key": "cf_state.enabled", "from": True, "to": False} in result["states"]
        assert result["summary"]["states_changed"] == 1

    def test_hw_mode_change_lands_in_states(self):
        a = _snap(hw_settings=S.HwFilterSettings(mode="src-ip"))
        b = _snap(hw_settings=S.HwFilterSettings(mode="mac"))
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        assert {"key": "hw_settings.mode", "from": "src-ip", "to": "mac"} in result["states"]

    def test_missing_hw_section_is_state_note_not_mass_removed(self):
        rules = [S.HwRuleSrcIp(id="h1", source_ip="10.0.0.1")]
        a = _snap(hw_settings=S.HwFilterSettings(mode="src-ip"), hw_rules_src_ip=rules)
        b = _snap(hw_settings=None)
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        assert _table(result, "hw_src_ip") == []  # incomparable, not "removed"
        assert {"key": "hw_settings.mode", "from": "src-ip", "to": None} in result["states"]

    def test_unsupported_hardware_rows_do_not_inflate_snapshot_count(self):
        """Partial legacy-firmware data is not a comparable hardware policy."""
        snap = _snap(
            hw_settings=None,
            hw_rules_src_ip=[S.HwRuleSrcIp(id="h1", source_ip="10.0.0.1")],
        )

        assert snap.counts()["hardware_rules"] == 0

    def test_alias_value_change_is_reported(self):
        a = _snap(aliases={"al1": S.Alias(id="al1", type="ip_list", values=["10.0.0.1"])})
        b = _snap(aliases={"al1": S.Alias(id="al1", type="ip_list", values=["10.0.0.1", "10.0.0.2"])})
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        (entry,) = _table(result, "aliases")
        assert entry["kind"] == "changed"
        assert {"field": "values", "from": ["10.0.0.1"], "to": ["10.0.0.1", "10.0.0.2"]} in entry["changed_fields"]

    def test_alias_and_user_order_never_reports_moved(self):
        aliases_a = {
            "al1": S.Alias(id="al1", values=["10.0.0.1"]),
            "al2": S.Alias(id="al2", values=["10.0.0.2"]),
        }
        aliases_b = {
            "al2": S.Alias(id="al2", values=["10.0.0.2"]),
            "al1": S.Alias(id="al1", values=["10.0.0.1"]),
        }
        users_a = [S.NgfwUser(id="u1"), S.NgfwUser(id="u2")]
        users_b = [S.NgfwUser(id="u2"), S.NgfwUser(id="u1")]

        result = snapshot_diff.diff_snapshots(
            _snap(aliases=aliases_a, users=users_a),
            _snap(aliases=aliases_b, users=users_b),
            anonymized=False,
        )

        assert result["tables"] == []
        assert result["summary"]["moved"] == 0

    def test_users_structural_fields_only(self):
        a = _snap(users=[S.NgfwUser(id="u1", name="Old Name", enabled=True)])
        b = _snap(users=[S.NgfwUser(id="u1", name="New Name", enabled=False)])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        (entry,) = _table(result, "users")
        fields = {f["field"] for f in entry["changed_fields"]}
        assert fields == {"enabled"}  # a renamed user alone is NOT a change

    def test_network_context_counts_are_covered_by_unordered_diff(self):
        """A changed collection counted by RulesSnapshot cannot yield a clean diff."""
        a = _snap(
            lan_networks=["10.10.0.0/16"],
            dns_zones=[S.DnsZone(id="zone-1", name="corp.example")],
            ngfw_addresses=["192.0.2.1"],
        )
        b = _snap(
            lan_networks=[],
            dns_zones=[],
            ngfw_addresses=[],
        )

        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)

        assert (
            a.counts()["lan_networks"] + a.counts()["dns_zones"] > b.counts()["lan_networks"] + b.counts()["dns_zones"]
        )
        assert {table["table"] for table in result["tables"]} == {"lan_networks", "dns_zones", "ngfw_addresses"}
        assert result["summary"] == {
            "added": 0,
            "removed": 3,
            "changed": 0,
            "moved": 0,
            "states_changed": 0,
            "tables_changed": 3,
        }
        for table in result["tables"]:
            (entry,) = table["entries"]
            assert entry["kind"] == "removed"
            assert entry["position_a"] is None
            assert entry["position_b"] is None


class TestAnonymizedMode:
    def test_display_only_difference_is_silent(self):
        a = _snap([_rule(1, comment="live comment", name="Live name")])
        b = _snap([_rule(1, comment="", name=None)])  # imported side: fields stripped
        result = snapshot_diff.diff_snapshots(a, b, anonymized=True)
        assert result["tables"] == []

    def test_user_id_references_collapse_to_user_n(self):
        user = S.NgfwUser(id="user.id.42", name="John", login="john")
        cf = S.ContentFilterRule(id="7", access="deny", aliases=["user.id.42"])
        cf_imported = S.ContentFilterRule(id="7", access="deny", aliases=["user-1"])
        a = _snap(users=[user], cf_rules=[cf])
        b = _snap(users=[S.NgfwUser(id="user-1")], cf_rules=[cf_imported])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=True)
        assert result["tables"] == []  # user-N normalization removes the noise

    def test_full_mode_still_reports_display_fields(self):
        a = _snap([_rule(1, comment="x")])
        b = _snap([_rule(1, comment="y")])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=False)
        assert _table(result, "fw_forward")[0]["changed_fields"] == [{"field": "comment", "from": "x", "to": "y"}]

    def test_anonymized_entries_never_carry_names(self):
        a = _snap([_rule(1, name="Secret rule name"), _rule(2)])
        b = _snap([_rule(2)])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=True)
        (entry,) = _table(result, "fw_forward")
        assert entry["kind"] == "removed"
        assert entry["name"] is None

    def test_real_change_still_visible_in_anonymized_mode(self):
        a = _snap([_rule(1, enabled=True)])
        b = _snap([_rule(1, enabled=False)])
        result = snapshot_diff.diff_snapshots(a, b, anonymized=True)
        (entry,) = _table(result, "fw_forward")
        assert entry["kind"] == "changed"
        assert entry["changed_fields"] == [{"field": "enabled", "from": True, "to": False}]

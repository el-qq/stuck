"""Tests for the pure access-compare diff engine (app/domain/access_compare.py).

``compare_stage_lists`` is a pure function of two fixed-order stage lists, so
these tests build minimal stage dicts directly. The honesty invariant (#7) is
the focus: ``unknown``/``na`` NEVER produce a ``divergent`` stage.
"""

from __future__ import annotations

from app.domain.access_compare import (
    ResolvedSubject,
    _divergence_reason,
    compare_stage_lists,
)
from app.domain.trace.contracts import STAGE_ORDER, stage


def _line(keys_status: dict[str, tuple[str, dict | None]]) -> list[dict]:
    """Build a full 12-stage list; unspecified keys default to pass/no-detail."""
    out = []
    for key in STAGE_ORDER:
        status, detail = keys_status.get(key, ("pass", None))
        out.append(stage(key, status, detail))
    return out


def _classify_map(stages) -> dict[str, str]:
    return {s["key"]: s["classification"] for s in stages}


class TestClassification:
    def test_all_same_when_identical(self):
        a = _line({})
        b = _line({})
        stages, primary = compare_stage_lists(a, b)
        assert primary is None
        assert all(s["classification"] == "same" for s in stages)
        assert len(stages) == len(STAGE_ORDER)

    def test_block_vs_pass_is_divergent_with_blocking_side(self):
        # Side A blocks at firewall; B passes there. B's firewall is definite.
        a = _line({"firewall": ("block", {"rule_id": "fw.1"})})
        # After A blocks, later A stages would be na in a real trace; here we
        # isolate the firewall stage only.
        b = _line({})
        stages, primary = compare_stage_lists(a, b)
        assert primary == "firewall"
        fw = next(s for s in stages if s["key"] == "firewall")
        assert fw["classification"] == "divergent"
        assert fw["divergence_kind"] == "status"
        assert fw["blocking_side"] == "a"

    def test_blocking_side_b(self):
        a = _line({})
        b = _line({"firewall": ("block", {"rule_id": "fw.9"})})
        stages, _ = compare_stage_lists(a, b)
        fw = next(s for s in stages if s["key"] == "firewall")
        assert fw["blocking_side"] == "b"

    def test_status_divergence_without_block_has_null_blocking_side(self):
        # pass vs limited: both definite, differ, neither blocks.
        a = _line({"rate_limit": ("limited", {"rule_id": "r.1"})})
        b = _line({})
        stages, _ = compare_stage_lists(a, b)
        rl = next(s for s in stages if s["key"] == "rate_limit")
        assert rl["classification"] == "divergent"
        assert rl["divergence_kind"] == "status"
        assert rl["blocking_side"] is None

    def test_same_status_different_rule_is_divergent(self):
        a = _line({"firewall": ("pass", {"rule_id": "fw.a"})})
        b = _line({"firewall": ("pass", {"rule_id": "fw.b"})})
        stages, primary = compare_stage_lists(a, b)
        fw = next(s for s in stages if s["key"] == "firewall")
        assert fw["classification"] == "divergent"
        assert fw["divergence_kind"] == "same_status_different_rule"
        assert fw["blocking_side"] is None
        assert primary == "firewall"

    def test_same_status_same_rule_is_same(self):
        a = _line({"firewall": ("pass", {"rule_id": "fw.x"})})
        b = _line({"firewall": ("pass", {"rule_id": "fw.x"})})
        stages, primary = compare_stage_lists(a, b)
        assert next(s for s in stages if s["key"] == "firewall")["classification"] == "same"
        assert primary is None


class TestHonestyInvariant:
    def test_unknown_vs_pass_is_incomparable_not_divergent(self):
        # The core #7 case: unknown on one side is NEVER a divergence.
        a = _line({"hw_filter": ("unknown", {"reason_key": "hw_source_ip_unknown"})})
        b = _line({})
        stages, primary = compare_stage_lists(a, b)
        hw = next(s for s in stages if s["key"] == "hw_filter")
        assert hw["classification"] == "incomparable"
        assert "divergence_kind" not in hw
        assert primary is None

    def test_unknown_vs_block_is_incomparable(self):
        a = _line({"firewall": ("unknown", None)})
        b = _line({"firewall": ("block", {"rule_id": "fw.1"})})
        stages, primary = compare_stage_lists(a, b)
        assert next(s for s in stages if s["key"] == "firewall")["classification"] == "incomparable"
        assert primary is None

    def test_both_unknown_is_incomparable(self):
        a = _line({"app_control": ("unknown", None)})
        b = _line({"app_control": ("unknown", None)})
        stages, _ = compare_stage_lists(a, b)
        assert next(s for s in stages if s["key"] == "app_control")["classification"] == "incomparable"

    def test_na_after_earlier_block_does_not_produce_late_divergence(self):
        # Case i.9: A blocks at content_filter, so its later stages are na. B
        # passes throughout. The divergence must be the EARLY block, and the
        # later na-vs-pass stages must be incomparable, not divergent.
        a = _line(
            {
                "content_filter": ("block", {"rule_id": "cf.1"}),
                "firewall": ("na", None),
                "ips": ("na", None),
                "destination": ("na", None),
            }
        )
        b = _line({})
        stages, primary = compare_stage_lists(a, b)
        assert primary == "content_filter"
        cls = _classify_map(stages)
        assert cls["content_filter"] == "divergent"
        assert cls["firewall"] == "incomparable"
        assert cls["ips"] == "incomparable"
        assert cls["destination"] == "incomparable"

    def test_identical_early_block_leaves_no_incomparable_stages(self):
        # Both subjects blocked at content_filter by the SAME rule: the later
        # stages are na on BOTH sides — an identical, fully-known state. Those
        # na/na pairs must be "same", not "incomparable" (the outcome is known
        # and equal, so this is not missing context).
        blocked = _line(
            {
                "content_filter": ("block", {"rule_id": "cf.1"}),
                "firewall": ("na", None),
                "ips": ("na", None),
                "destination": ("na", None),
            }
        )
        stages, primary = compare_stage_lists(blocked, [dict(s) for s in blocked])
        assert primary is None
        cls = _classify_map(stages)
        assert cls["content_filter"] == "same"
        assert cls["firewall"] == "same"
        assert cls["ips"] == "same"
        assert cls["destination"] == "same"
        assert not any(s["classification"] == "incomparable" for s in stages)


class TestPrimaryDivergence:
    def test_first_divergent_stage_wins(self):
        a = _line(
            {
                "dnat": ("applied", {"rule_id": "d.1"}),
                "firewall": ("block", {"rule_id": "fw.1"}),
            }
        )
        b = _line({})
        _, primary = compare_stage_lists(a, b)
        # dnat diverges (applied vs pass) before firewall → dnat is primary.
        assert primary == "dnat"


class TestDivergenceReason:
    def test_identical_subjects(self):
        stages, _ = compare_stage_lists(_line({}), _line({}))
        assert _divergence_reason(None, stages, identical_subjects=True) == "identical"

    def test_diverged(self):
        a = _line({"firewall": ("block", {"rule_id": "fw.1"})})
        stages, primary = compare_stage_lists(a, _line({}))
        assert _divergence_reason(primary, stages, identical_subjects=False) == "diverged"

    def test_context_incomplete(self):
        a = _line({"hw_filter": ("unknown", None)})
        stages, primary = compare_stage_lists(a, _line({}))
        assert primary is None
        assert _divergence_reason(primary, stages, identical_subjects=False) == "context_incomplete"

    def test_none_when_all_same_but_distinct_subjects(self):
        stages, primary = compare_stage_lists(_line({}), _line({}))
        assert _divergence_reason(primary, stages, identical_subjects=False) is None

    def test_none_when_both_blocked_identically(self):
        # Regression: two distinct subjects blocked by the same early rule are
        # equally, fully known — the banner must read "no differences", not
        # "context_incomplete" (the na/na tail is not missing context).
        blocked = _line(
            {
                "content_filter": ("block", {"rule_id": "cf.1"}),
                "firewall": ("na", None),
                "destination": ("na", None),
            }
        )
        stages, primary = compare_stage_lists(blocked, [dict(s) for s in blocked])
        assert _divergence_reason(primary, stages, identical_subjects=False) is None


class TestResolvedSubject:
    def test_user_id_helper(self):
        class _U:
            id = "user.id.7"

        assert ResolvedSubject(_U(), "10.0.0.1").user_id == "user.id.7"
        assert ResolvedSubject(None, None).user_id is None

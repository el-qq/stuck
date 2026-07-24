"""Access comparison: two subjects, one snapshot, one target, per-stage diff.

The feature answers "why does traffic pass for one subject but not another"
without touching NGFW configuration. Both sides are ordinary read-only traces
(``trace_engine.run_trace``) evaluated on the SAME snapshot and the SAME shared
target context, so any difference is attributable to the subject alone.

Honesty invariant (AGENTS.md #7): ``unknown`` NEVER produces a ``divergent``
stage. "unknown vs allow/block" is ``incomparable`` (incomplete context), not a
discovered cause of difference. Only two definite, differing statuses — or two
equal statuses reached by different rules — count as a real divergence.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from ..ngfw import schemas as S
from ..ngfw.client import NgfwClient
from . import trace_engine
from .binding_pool import RulesSnapshot

# ``unknown`` = the read-only context needed to decide this stage is missing;
# it may never be used as evidence of a difference (honesty invariant #7).
# ``na`` = the stage was not reached because an earlier stage already decided
# the outcome — a known, not a missing, state (handled explicitly below).
_UNKNOWN = "unknown"
_NOT_APPLICABLE = "na"

StageClassification = Literal["same", "divergent", "incomparable"]
Side = Literal["a", "b"]


@dataclass(frozen=True)
class ResolvedSubject:
    """A fully resolved side subject: an optional user and an optional IP."""

    user: S.NgfwUser | None
    source_ip: str | None

    @property
    def user_id(self) -> str | None:
        return str(self.user.id) if self.user is not None else None


def _rule_id(stage: dict[str, Any]) -> str | None:
    return (stage.get("detail") or {}).get("rule_id")


def _classify_stage(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Classify one aligned stage pair as same / divergent / incomparable.

    Ordered precedence, honesty-first:
    1. Either side ``unknown`` → ``incomparable`` (missing context, never a
       proven difference).
    2. Both sides ``na`` → ``same``: neither reached this stage because an
       earlier stage already decided both — an identical, fully-known state
       (e.g. both blocked by the same upstream rule), not missing context.
    3. Exactly one side ``na`` → ``incomparable``: that side stopped earlier, so
       the stage cannot be compared (the real difference is the upstream stage).
    4. Different definite statuses → ``divergent`` (kind ``status``); if exactly
       one side blocks, ``blocking_side`` names it.
    5. Equal statuses but different matched ``rule_id`` → ``divergent`` (kind
       ``same_status_different_rule``): both sides proceed, by different rules.
    6. Otherwise → ``same``.
    """
    entry: dict[str, Any] = {
        "key": a["key"],
        "order": a["order"],
        "title_key": a["title_key"],
        "a": a,
        "b": b,
    }

    status_a, status_b = a["status"], b["status"]
    if status_a == _UNKNOWN or status_b == _UNKNOWN:
        entry["classification"] = "incomparable"
        return entry
    if status_a == _NOT_APPLICABLE and status_b == _NOT_APPLICABLE:
        entry["classification"] = "same"
        return entry
    if status_a == _NOT_APPLICABLE or status_b == _NOT_APPLICABLE:
        entry["classification"] = "incomparable"
        return entry

    if status_a != status_b:
        blocking: Side | None = None
        if status_a == "block" and status_b != "block":
            blocking = "a"
        elif status_b == "block" and status_a != "block":
            blocking = "b"
        entry["classification"] = "divergent"
        entry["divergence_kind"] = "status"
        entry["blocking_side"] = blocking
        return entry

    if _rule_id(a) != _rule_id(b):
        entry["classification"] = "divergent"
        entry["divergence_kind"] = "same_status_different_rule"
        entry["blocking_side"] = None
        return entry

    entry["classification"] = "same"
    return entry


def compare_stage_lists(
    a_stages: list[dict[str, Any]], b_stages: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], str | None]:
    """Diff two fixed-order stage lists; return stages + first divergent key.

    The pipeline order is identical for both sides (AGENTS.md #6), so stages are
    aligned by position. ``primary_divergence`` is the key of the first stage
    classified ``divergent`` — never an ``incomparable`` one.
    """
    stages: list[dict[str, Any]] = []
    primary_divergence: str | None = None
    for a, b in zip(a_stages, b_stages, strict=True):
        entry = _classify_stage(a, b)
        if entry["classification"] == "divergent" and primary_divergence is None:
            primary_divergence = entry["key"]
        stages.append(entry)
    return stages, primary_divergence


def _divergence_reason(
    primary_divergence: str | None,
    stages: list[dict[str, Any]],
    identical_subjects: bool,
) -> str | None:
    """Summarize the diff outcome for the UI banner (honest about unknowns)."""
    if identical_subjects:
        return "identical"
    if primary_divergence is not None:
        return "diverged"
    if any(stage["classification"] == "incomparable" for stage in stages):
        # Verdicts may differ, but only through incomplete context — never
        # presented as a proven configuration difference.
        return "context_incomplete"
    return None


def _side_payload(trace: dict[str, Any], subject: ResolvedSubject) -> dict[str, Any]:
    return {
        "subject": {"user": trace["user"], "source_ip": trace["target"]["source_ip"]},
        "context": {
            "has_user": subject.user is not None,
            "has_source_ip": subject.source_ip is not None,
        },
        "target": trace["target"],
        "summary": trace["summary"],
    }


async def run_access_compare(
    snapshot: RulesSnapshot,
    client: NgfwClient,
    *,
    url: str,
    protocol: str,
    dst_port_override: int | None,
    subject_a: ResolvedSubject,
    subject_b: ResolvedSubject,
) -> dict[str, Any]:
    """Run both sides on one snapshot and one shared target, then diff them.

    The subject-independent target facts (categorization, DNS) are resolved once
    and injected into both traces so the two sides cannot artificially diverge
    on the target; the two subject-dependent traces then run under a single
    ``asyncio.gather`` batch.
    """
    context = await trace_engine.resolve_target_context(snapshot, client, url=url, dst_port_override=dst_port_override)
    trace_a, trace_b = await asyncio.gather(
        trace_engine.run_trace(
            snapshot,
            client,
            url=url,
            user=subject_a.user,
            protocol=protocol,
            dst_port_override=dst_port_override,
            source_ip=subject_a.source_ip,
            context=context,
        ),
        trace_engine.run_trace(
            snapshot,
            client,
            url=url,
            user=subject_b.user,
            protocol=protocol,
            dst_port_override=dst_port_override,
            source_ip=subject_b.source_ip,
            context=context,
        ),
    )

    stages, primary_divergence = compare_stage_lists(trace_a["stages"], trace_b["stages"])
    identical_subjects = subject_a.user_id == subject_b.user_id and subject_a.source_ip == subject_b.source_ip
    return {
        "a": _side_payload(trace_a, subject_a),
        "b": _side_payload(trace_b, subject_b),
        # Categories are a target fact: identical for both sides by construction.
        "categories": trace_a["categories"],
        "stages": stages,
        "primary_divergence": primary_divergence,
        "divergence_reason": _divergence_reason(primary_divergence, stages, identical_subjects),
        "identical_subjects": identical_subjects,
    }

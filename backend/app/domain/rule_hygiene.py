"""Public entry point for static, read-only rule-hygiene analysis.

The implementation is split by configuration area in :mod:`.hygiene`:
firewall-chain coverage is independent of hardware-filter list analysis.  This
module keeps the stable import path used by API handlers and integrations.
"""

from __future__ import annotations

from .binding_pool import RulesSnapshot
from .hygiene.firewall import analyze_chain
from .hygiene.hardware import analyze_hardware
from .hygiene.models import HygieneFinding

_FIREWALL_CHAINS: tuple[str, ...] = ("fw_forward", "fw_input")


def analyze_snapshot(snapshot: RulesSnapshot) -> dict:
    """Run all pure hygiene checks and return the established API shape."""
    findings: list[HygieneFinding] = []
    for table in _FIREWALL_CHAINS:
        findings.extend(analyze_chain(table, getattr(snapshot, table)))
    findings.extend(analyze_hardware(snapshot))

    summary = {"total": len(findings), "risk": 0, "warning": 0, "info": 0, "possible": 0}
    for finding in findings:
        summary[finding.severity] += 1
        if finding.tier == "possible":
            summary["possible"] += 1

    return {"summary": summary, "findings": [finding.to_dict() for finding in findings]}

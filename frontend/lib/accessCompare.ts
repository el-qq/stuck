/**
 * Offline mirror of the backend's canonical stage classification (docs/source/
 * comparison.md §3.e, decision B). The LIVE feature never runs this — a real
 * `POST /api/trace/compare` response already carries `classification` per
 * stage, computed once, server-side, on one snapshot (fork d). This function
 * exists only so the offline demo (`frontend/lib/demoData.ts`) can produce a
 * contract-shaped `CompareResponse` from two local `TraceResponse` fixtures
 * without contacting a backend, exactly like `runDemoTrace` already mirrors
 * `trace_engine.run_trace` for the single-trace demo.
 */
import { CompareStage, StageKey, StageStatus, TraceStage } from "./types";

/** `unknown`/`na` never count as a proven difference (invariant №7) — a stage
 * where either side is undetermined is `incomparable`, not `divergent`. */
const UNDETERMINED: readonly StageStatus[] = ["unknown", "na"];

export interface ClassifiedCompare {
  stages: CompareStage[];
  primary_divergence: StageKey | null;
  // Stage-level outcome only. `null` = every stage matched (no divergence, no
  // incomplete context). Whether the two SUBJECTS are the same is a separate
  // response-level flag (`identical_subjects`), which the caller sets and which
  // maps to the `"identical"` reason — mirroring the backend precedence in
  // `_divergence_reason` (docs/source/comparison.md §3.e).
  divergence_reason: "diverged" | "context_incomplete" | null;
}

/** Pairs two equal-length, same-ordered stage lists (guaranteed by the fixed
 * pipeline order, invariant №6) and classifies each pair per §3.e. */
export function classifyCompareStages(a: readonly TraceStage[], b: readonly TraceStage[]): ClassifiedCompare {
  const byKeyB = new Map(b.map((stage) => [stage.key, stage]));

  const stages: CompareStage[] = a.map((sideA) => {
    const sideB = byKeyB.get(sideA.key) ?? sideA;
    const base = { key: sideA.key, order: sideA.order, title_key: sideA.title_key, a: sideA, b: sideB };

    if (UNDETERMINED.includes(sideA.status) || UNDETERMINED.includes(sideB.status)) {
      return { ...base, classification: "incomparable" };
    }
    if (sideA.status !== sideB.status) {
      const blocking_side = sideA.status === "block" ? "a" : sideB.status === "block" ? "b" : null;
      return { ...base, classification: "divergent", divergence_kind: "status", blocking_side };
    }
    const ruleA = sideA.detail?.rule_id;
    const ruleB = sideB.detail?.rule_id;
    if (ruleA && ruleB && ruleA !== ruleB) {
      return { ...base, classification: "divergent", divergence_kind: "same_status_different_rule", blocking_side: null };
    }
    return { ...base, classification: "same" };
  });

  const primaryIndex = stages.findIndex((stage) => stage.classification === "divergent");
  if (primaryIndex !== -1) {
    return { stages, primary_divergence: stages[primaryIndex]!.key, divergence_reason: "diverged" };
  }
  if (stages.some((stage) => stage.classification === "incomparable")) {
    return { stages, primary_divergence: null, divergence_reason: "context_incomplete" };
  }
  // Every stage matched. At the stage level there is no divergence reason; the
  // backend returns `null` here too (a `"identical"` reason means identical
  // subjects, decided response-level, not "same access outcome").
  return { stages, primary_divergence: null, divergence_reason: null };
}

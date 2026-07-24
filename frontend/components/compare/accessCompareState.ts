import type { TraceTargetController } from "@/hooks/useTraceTarget";
import type { TraceSubjectsState } from "@/hooks/useTraceSubjects";
import { CompareResponse } from "@/lib/types";

/**
 * A side's subject is the same shape as a single trace subject (docs/source/
 * comparison.md §3.b): a user, a raw source IP with no identity, or neither
 * ("no specific subject" — identity-only, mirrors the check tab's "all" mode).
 * `useTraceSubjects` only distinguishes "all"/"user"; the "ip" case is unique
 * to compare (the check tab never lets an administrator type a raw source IP
 * with no user attached), so it is tracked alongside it here.
 */
export type CompareSubjectMode = "none" | "user" | "ip";

/** One side's input state, shared verbatim by the live hook and the demo
 * adapter so `AccessCompareSideControl` never has to special-case either. */
export interface AccessCompareSideState {
  mode: CompareSubjectMode;
  setMode: (mode: CompareSubjectMode) => void;
  /** Populated (and fetched) only while `mode === "user"`. */
  subjects: TraceSubjectsState;
  manualIp: string;
  setManualIp: (ip: string) => void;
  /** False while a required choice (a user, an unambiguous source IP, or a
   * non-empty manual IP) is still missing — gates the submit button. */
  ready: boolean;
  /** Localized per-side message from a `compare_side_invalid` response
   * (fork i, cases 2-4) — shown under this side's controls, never as a
   * page-wide banner (invariant: per-side problems address that side only). */
  errorText: string | null;
}

/** UI contract shared by the live API hook (`useAccessCompare`) and the fully
 * local demo adapter (`useDemoAccessCompare`). Presentation components (the
 * input panel and `AccessCompareView`) receive no API client or session. */
export interface AccessCompareState {
  target: TraceTargetController;
  sideA: AccessCompareSideState;
  sideB: AccessCompareSideState;
  canSubmit: boolean;
  submitting: boolean;
  runCompare: () => void;
  /** Clears a shown result after `rules/refresh` (docs/source/comparison.md
   * §3.i case 6) — it was computed on a snapshot that no longer exists. */
  invalidateResult: () => void;
  result: CompareResponse | null;
  /** Non-per-side failure (e.g. `not_found` when the feature flag is off,
   * `insufficient_ngfw_permissions`, a network error). */
  error: string | null;
  traceAllowed: boolean;
  rulesLoaded: boolean;
  /** Backend mutations are meaningless in demo mode; kept for parity with the
   * other workspace state shapes (`SnapshotWorkspaceState`). */
  backendActionsAvailable: boolean;
}

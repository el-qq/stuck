import type { Protocol, TraceResponse } from "@/lib/types";
import type { TraceMode, TraceSubjectsState } from "@/hooks/useTraceSubjects";
import type { TraceTargetController } from "@/hooks/useTraceTarget";

export interface TraceSubmitPayload {
  url: string;
  /** Always sent explicitly — including the "any" default — so the backend
   *  never has to guess which protocol filter was intended. */
  protocol: Protocol;
  userId?: string;
  sourceIp?: string;
}

/**
 * UI contract shared by the live check hook (`useCheck`) and the fully local
 * demo adapter (`useDemoCheck`) — the same pattern as `AccessCompareState`
 * (`components/compare/accessCompareState.ts`) and `SnapshotWorkspaceState`.
 * Presentational components (`TraceCheckPanel`, `TraceCheckWorkspace`)
 * receive no API client or session.
 */
export interface CheckState {
  mode: TraceMode;
  setMode: (mode: TraceMode) => void;
  /** Transport sent with the check; a missing protocol defaults to "any"
   *  (every protocol) server-side. */
  protocol: Protocol;
  setProtocol: (protocol: Protocol) => void;
  target: TraceTargetController;
  subjects: TraceSubjectsState;
  rulesLoaded: boolean;
  /** False when the backend has identified a known insufficient NGFW role. */
  traceAllowed: boolean;
  submitting: boolean;
  result: TraceResponse | null;
  runCheck: (payload: TraceSubmitPayload) => void;
}

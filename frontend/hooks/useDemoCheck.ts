"use client";

import { useCallback, useState } from "react";
import { useI18n } from "@/i18n";
import { DEMO_USERS, demoTargetForInput, runDemoTrace } from "@/lib/demoData";
import { DEFAULT_PROTOCOL } from "@/lib/protocol";
import { Protocol, TraceResponse } from "@/lib/types";
import type { CheckState, TraceSubmitPayload } from "@/components/trace/checkState";
import type { TraceMode } from "@/hooks/useTraceSubjects";
import { useDemoTraceSubjects } from "@/hooks/useDemoTraceSubjects";
import { useDemoTraceTarget } from "@/hooks/useDemoTraceTarget";

/** Fully local adapter for the check tab. It has no API/session imports: the
 * result is computed by `runDemoTrace` from the chosen local fixture target. */
export function useDemoCheck(): CheckState {
  const { t } = useI18n();
  const [mode, setMode] = useState<TraceMode>("all");
  const [protocol, setProtocol] = useState<Protocol>(DEFAULT_PROTOCOL);
  const target = useDemoTraceTarget();
  const subjects = useDemoTraceSubjects(mode);
  const [result, setResult] = useState<TraceResponse | null>(null);

  const runCheck = useCallback(
    (payload: TraceSubmitPayload) => {
      const user = payload.userId ? (DEMO_USERS.find((candidate) => candidate.id === payload.userId) ?? null) : null;
      setResult(runDemoTrace(demoTargetForInput(payload.url), user, t, payload.sourceIp, payload.protocol));
    },
    [t],
  );

  return { mode, setMode, protocol, setProtocol, target, subjects, rulesLoaded: true, traceAllowed: true, submitting: false, result, runCheck };
}

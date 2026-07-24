"use client";

import { useCallback, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { toApiError } from "@/lib/errors";
import { DEFAULT_PROTOCOL } from "@/lib/protocol";
import { Protocol, TraceResponse } from "@/lib/types";
import type { CheckState, TraceSubmitPayload } from "@/components/trace/checkState";
import { useTraceSubjects, TraceMode } from "@/hooks/useTraceSubjects";
import { useTraceTarget } from "@/hooks/useTraceTarget";

interface UseCheckOptions {
  rulesLoaded: boolean;
  /** False when the backend has identified a known insufficient NGFW role. */
  traceAllowed: boolean;
  /** Bumped after a successful rules refresh — invalidates the cached
   * users/source-address lookups, mirroring `useAccessCompare`'s option. */
  usersVersion: number;
}

/** Owns the live check tab: its target/subject/protocol controls and the
 * `POST /api/trace` request. */
export function useCheck({ rulesLoaded, traceAllowed, usersVersion }: UseCheckOptions): CheckState {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();

  const [mode, setMode] = useState<TraceMode>("all");
  const [protocol, setProtocol] = useState<Protocol>(DEFAULT_PROTOCOL);
  const target = useTraceTarget();
  const subjects = useTraceSubjects({ mode, rulesLoaded, usersVersion });

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<TraceResponse | null>(null);

  const runCheck = useCallback(
    (payload: TraceSubmitPayload) => {
      if (!traceAllowed) return;
      setSubmitting(true);
      void api
        .trace({
          url: payload.url,
          // Sent explicitly (including the "any" default) so the backend
          // never has to guess which protocol filter was intended.
          protocol: payload.protocol,
          ...(payload.userId ? { user_id: payload.userId } : {}),
          ...(payload.sourceIp ? { source_ip: payload.sourceIp } : {}),
        })
        .then((res) => {
          setResult(res);
          // v2: trace reports which snapshot it ran on (covers lazy first load).
          session.markRulesUpdated(res.rules_updated_at);
        })
        .catch((caught: unknown) => {
          const apiErr = toApiError(caught);
          if (!session.handleAuthError(apiErr)) toast.show(errorMessage(apiErr), "error");
        })
        .finally(() => setSubmitting(false));
    },
    [errorMessage, session, toast, traceAllowed],
  );

  return { mode, setMode, protocol, setProtocol, target, subjects, rulesLoaded, traceAllowed, submitting, result, runCheck };
}

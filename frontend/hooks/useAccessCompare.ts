"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { useI18n } from "@/i18n";
import * as api from "@/lib/api";
import { toApiError } from "@/lib/errors";
import { CompareRequest, CompareResponse, CompareSubject, Protocol } from "@/lib/types";
import { DEFAULT_PROTOCOL } from "@/lib/protocol";
import { compareErrorSide, compareSideReasonKey } from "@/components/compare/accessComparePresentation";
import type { AccessCompareSideState, AccessCompareState, CompareSubjectMode } from "@/components/compare/accessCompareState";
import { useTraceSubjects, TraceSubjectsState } from "@/hooks/useTraceSubjects";
import { useTraceTarget } from "@/hooks/useTraceTarget";

interface UseAccessCompareOptions {
  rulesLoaded: boolean;
  traceAllowed: boolean;
  /** Bumped after a successful rules refresh — invalidates both sides' cached
   * users/source-address lookups, mirroring `TraceForm`'s `usersVersion`. */
  usersVersion: number;
}

function sideReady(mode: CompareSubjectMode, subjects: TraceSubjectsState, manualIp: string): boolean {
  if (mode === "none") return true;
  if (mode === "ip") return manualIp.trim().length > 0;
  // A failed source-address load leaves the list empty, which is NOT proof the
  // user has no address — submitting then risks a server-side
  // `multiple_source_ips` rejection with no way to pick one. Block until the
  // addresses actually load (error clears on retry).
  if (!subjects.selectedUser || subjects.sourceAddressesLoading || subjects.sourceAddressesError) return false;
  return subjects.sourceAddresses.length === 0 || !!subjects.selectedSourceIp;
}

function buildSubject(mode: CompareSubjectMode, subjects: TraceSubjectsState, manualIp: string): CompareSubject {
  if (mode === "user") {
    return {
      ...(subjects.selectedUser ? { user_id: subjects.selectedUser.id } : {}),
      ...(subjects.selectedSourceIp ? { source_ip: subjects.selectedSourceIp } : {}),
    };
  }
  if (mode === "ip") {
    const ip = manualIp.trim();
    return ip ? { source_ip: ip } : {};
  }
  return {};
}

/** Owns both compared subjects, the shared target and the live `/api/trace/compare`
 * request. One monotonic request token makes it fail closed: a response for a
 * superseded request (rules refreshed mid-flight, or a second submit) never
 * overwrites the result for what is now on screen. */
export function useAccessCompare({ rulesLoaded, traceAllowed, usersVersion }: UseAccessCompareOptions): AccessCompareState {
  const session = useSession();
  const errorMessage = useApiErrorMessage();
  const { t } = useI18n();

  const target = useTraceTarget();

  const [protocol, setProtocol] = useState<Protocol>(DEFAULT_PROTOCOL);
  const [modeA, setModeA] = useState<CompareSubjectMode>("none");
  const [modeB, setModeB] = useState<CompareSubjectMode>("none");
  const [manualIpA, setManualIpA] = useState("");
  const [manualIpB, setManualIpB] = useState("");
  const subjectsA = useTraceSubjects({ mode: modeA === "user" ? "user" : "all", rulesLoaded, usersVersion });
  const subjectsB = useTraceSubjects({ mode: modeB === "user" ? "user" : "all", rulesLoaded, usersVersion });

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<CompareResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sideAError, setSideAError] = useState<string | null>(null);
  const [sideBError, setSideBError] = useState<string | null>(null);
  const requestVersion = useRef(0);

  const readyA = sideReady(modeA, subjectsA, manualIpA);
  const readyB = sideReady(modeB, subjectsB, manualIpB);
  const canSubmit = traceAllowed && rulesLoaded && target.address.trim().length > 0 && readyA && readyB && !submitting;

  const invalidateResult = useCallback(() => {
    requestVersion.current += 1; // cancel any in-flight response before clearing
    setResult(null);
    setError(null);
    setSideAError(null);
    setSideBError(null);
  }, []);

  const runCompare = useCallback(() => {
    if (!traceAllowed || !rulesLoaded || !readyA || !readyB || target.address.trim().length === 0 || submitting) return;
    const requestId = requestVersion.current + 1;
    requestVersion.current = requestId;
    setSubmitting(true);
    setError(null);
    setSideAError(null);
    setSideBError(null);
    const url = target.submitTarget();
    const payload: CompareRequest = {
      url,
      protocol,
      a: buildSubject(modeA, subjectsA, manualIpA),
      b: buildSubject(modeB, subjectsB, manualIpB),
    };
    void api
      .compareAccess(payload)
      .then((res) => {
        if (requestVersion.current !== requestId) return;
        setResult(res);
        session.markRulesUpdated(res.rules_updated_at);
      })
      .catch((caught: unknown) => {
        if (requestVersion.current !== requestId) return;
        const apiErr = toApiError(caught);
        if (session.handleAuthError(apiErr)) return;
        const side = compareErrorSide(apiErr);
        const reasonKey = compareSideReasonKey(apiErr);
        const message = reasonKey ? t(reasonKey) : errorMessage(apiErr);
        if (side === "a") setSideAError(message);
        else if (side === "b") setSideBError(message);
        else setError(errorMessage(apiErr));
      })
      .finally(() => {
        if (requestVersion.current === requestId) setSubmitting(false);
      });
  }, [
    errorMessage,
    manualIpA,
    manualIpB,
    modeA,
    modeB,
    protocol,
    readyA,
    readyB,
    rulesLoaded,
    session,
    subjectsA,
    subjectsB,
    submitting,
    t,
    target,
    traceAllowed,
  ]);

  const sideA = useMemo<AccessCompareSideState>(
    () => ({ mode: modeA, setMode: setModeA, subjects: subjectsA, manualIp: manualIpA, setManualIp: setManualIpA, ready: readyA, errorText: sideAError }),
    [manualIpA, modeA, readyA, sideAError, subjectsA],
  );
  const sideB = useMemo<AccessCompareSideState>(
    () => ({ mode: modeB, setMode: setModeB, subjects: subjectsB, manualIp: manualIpB, setManualIp: setManualIpB, ready: readyB, errorText: sideBError }),
    [manualIpB, modeB, readyB, sideBError, subjectsB],
  );

  return {
    target,
    protocol,
    setProtocol,
    sideA,
    sideB,
    canSubmit,
    submitting,
    runCompare,
    invalidateResult,
    result,
    error,
    traceAllowed,
    rulesLoaded,
    backendActionsAvailable: true,
  };
}

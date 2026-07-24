"use client";

import { useCallback, useMemo, useState } from "react";
import { DEMO_ACCESS_COMPARE, DemoCompareSubject, runDemoCompare } from "@/lib/demoData";
import { CompareResponse, Protocol } from "@/lib/types";
import { DEFAULT_PROTOCOL } from "@/lib/protocol";
import type { AccessCompareSideState, AccessCompareState, CompareSubjectMode } from "@/components/compare/accessCompareState";
import type { TraceSubjectsState } from "@/hooks/useTraceSubjects";
import { useDemoTraceSubjects } from "@/hooks/useDemoTraceSubjects";
import { useDemoTraceTarget } from "@/hooks/useDemoTraceTarget";

/** The same two illustrative users `DEMO_ACCESS_COMPARE` uses, pre-selected
 * the moment either side switches to "User" mode — a shortcut toward
 * reproducing something close to the pre-loaded showcase below, without
 * claiming the (initially "no subject") form already matches it. */
const DEFAULT_SIDE_A_USER_ID = "u2"; // Svetlana Petrova — office LAN, one assigned IP.
const DEFAULT_SIDE_B_USER_ID = "u6"; // Guest #204 — no active/assigned IP.

function demoSideReady(mode: CompareSubjectMode, subjects: TraceSubjectsState, manualIp: string): boolean {
  if (mode === "none") return true;
  if (mode === "ip") return manualIp.trim().length > 0;
  if (!subjects.selectedUser) return false;
  return subjects.sourceAddresses.length === 0 || !!subjects.selectedSourceIp;
}

function demoSubjectFrom(mode: CompareSubjectMode, subjects: TraceSubjectsState, manualIp: string): DemoCompareSubject {
  if (mode === "user") return { user: subjects.selectedUser, sourceIp: subjects.selectedSourceIp };
  if (mode === "ip") {
    const ip = manualIp.trim();
    return { user: null, sourceIp: ip || null };
  }
  return { user: null, sourceIp: null };
}

/**
 * Fully local adapter for the access-compare tab. Unlike `useDemoRuleSnapshots`
 * or the check tab's `useDemoCheck`, this tab starts with a rich hand-built
 * result (`DEMO_ACCESS_COMPARE`) already showing — it packs every
 * classification the feature can produce into one screen, which the local
 * `runDemoCompare` engine intentionally does not attempt to reproduce for
 * arbitrary input (see its doc comment in `lib/demoData.ts`). The form itself
 * starts with the same defaults the live tab does ("no subject" on both
 * sides) rather than mirroring the showcase's inputs, so there is no implied
 * continuity between the pre-loaded example and a fresh, genuinely local
 * computation. Once the administrator edits the form and runs Compare, the
 * result comes from `runDemoCompare`, computed entirely in the browser.
 */
export function useDemoAccessCompare(): AccessCompareState {
  const target = useDemoTraceTarget();
  const [protocol, setProtocol] = useState<Protocol>(DEFAULT_PROTOCOL);
  const [modeA, setModeA] = useState<CompareSubjectMode>("none");
  const [modeB, setModeB] = useState<CompareSubjectMode>("none");
  const [manualIpA, setManualIpA] = useState("");
  const [manualIpB, setManualIpB] = useState("");
  const subjectsA = useDemoTraceSubjects(modeA === "user" ? "user" : "all", DEFAULT_SIDE_A_USER_ID);
  const subjectsB = useDemoTraceSubjects(modeB === "user" ? "user" : "all", DEFAULT_SIDE_B_USER_ID);

  const [result, setResult] = useState<CompareResponse | null>(DEMO_ACCESS_COMPARE);

  const readyA = demoSideReady(modeA, subjectsA, manualIpA);
  const readyB = demoSideReady(modeB, subjectsB, manualIpB);
  const canSubmit = target.address.trim().length > 0 && readyA && readyB;

  const runCompare = useCallback(() => {
    if (!canSubmit) return;
    const url = target.submitTarget();
    setResult(runDemoCompare(url, protocol, demoSubjectFrom(modeA, subjectsA, manualIpA), demoSubjectFrom(modeB, subjectsB, manualIpB)));
  }, [canSubmit, manualIpA, manualIpB, modeA, modeB, protocol, subjectsA, subjectsB, target]);

  const invalidateResult = useCallback(() => setResult(null), []);

  const sideA = useMemo<AccessCompareSideState>(
    () => ({ mode: modeA, setMode: setModeA, subjects: subjectsA, manualIp: manualIpA, setManualIp: setManualIpA, ready: readyA, errorText: null }),
    [manualIpA, modeA, readyA, subjectsA],
  );
  const sideB = useMemo<AccessCompareSideState>(
    () => ({ mode: modeB, setMode: setModeB, subjects: subjectsB, manualIp: manualIpB, setManualIp: setManualIpB, ready: readyB, errorText: null }),
    [manualIpB, modeB, readyB, subjectsB],
  );

  return {
    target,
    protocol,
    setProtocol,
    sideA,
    sideB,
    canSubmit,
    submitting: false,
    runCompare,
    invalidateResult,
    result,
    error: null,
    traceAllowed: true,
    rulesLoaded: true,
    backendActionsAvailable: false,
  };
}

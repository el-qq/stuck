"use client";

import React, { useState } from "react";
import { useTraceSubjects } from "@/hooks/useTraceSubjects";
import { useTraceTarget } from "@/hooks/useTraceTarget";
import { TraceCheckPanel } from "./TraceCheckPanel";

export interface TraceSubmitPayload {
  url: string;
  userId?: string;
  sourceIp?: string;
}

interface Props {
  rulesLoaded: boolean;
  /** False when the backend has identified a known insufficient NGFW role. */
  traceAllowed: boolean;
  submitting: boolean;
  /** Bumped after a successful rules refresh, invalidating local subject data. */
  usersVersion: number;
  onSubmit: (payload: TraceSubmitPayload) => void;
}

/** Compose trace-target controls with the optional user/source-IP scenario. */
export function TraceForm({ rulesLoaded, traceAllowed, submitting, usersVersion, onSubmit }: Props) {
  const [mode, setMode] = useState<"all" | "user">("all");
  const target = useTraceTarget();
  const subjects = useTraceSubjects({ mode, rulesLoaded, usersVersion });
  return (
    <TraceCheckPanel
      rulesLoaded={rulesLoaded}
      traceAllowed={traceAllowed}
      submitting={submitting}
      mode={mode}
      onModeChange={setMode}
      target={target}
      subjects={subjects}
      onSubmit={onSubmit}
    />
  );
}

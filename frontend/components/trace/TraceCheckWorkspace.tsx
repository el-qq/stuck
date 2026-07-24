"use client";

import React, { useRef } from "react";
import { useI18n } from "@/i18n";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";
import { CheckWorkspace, EmptyTraceResult } from "./CheckWorkspace";
import { TraceCheckPanel } from "./TraceCheckPanel";
import { TraceResult } from "./TraceResult";
import type { CheckState } from "./checkState";

interface Props {
  state: CheckState;
  /** Public configuration is resolved at the screen boundary; the offline
   * demo supplies its own safe default so this stays reusable there. */
  traceAnimationEnabled?: boolean;
  ngfwServer?: string;
  ngfwPort?: number;
}

/**
 * Shared check-tab workspace for both the live and offline-demo screens. The
 * "trace disabled" warning is driven entirely by `state.traceAllowed` — the
 * demo's `CheckState` always reports it `true`, so the banner stays absent
 * there without any extra conditional here.
 */
export function TraceCheckWorkspace({ state, traceAnimationEnabled = true, ngfwServer, ngfwPort }: Props) {
  const { t } = useI18n();
  const resultRef = useRef<HTMLElement>(null);
  useMobileResultScroll(resultRef, state.result);

  return (
    <CheckWorkspace
      resultRef={resultRef}
      controls={
        <>
          {!state.traceAllowed && (
            <div
              role="alert"
              data-testid="access-warning"
              style={{
                marginBottom: 14,
                borderRadius: "var(--radius-sm)",
                padding: "11px 13px",
                color: "var(--warn)",
                background: "var(--warn-soft)",
                fontSize: 13,
                lineHeight: 1.45,
              }}
            >
              {t("access.persistentWarning")}
            </div>
          )}
          <TraceCheckPanel
            rulesLoaded={state.rulesLoaded}
            traceAllowed={state.traceAllowed}
            submitting={state.submitting}
            mode={state.mode}
            onModeChange={state.setMode}
            target={state.target}
            protocol={state.protocol}
            onProtocolChange={state.setProtocol}
            subjects={state.subjects}
            onSubmit={state.runCheck}
          />
        </>
      }
      result={
        state.result ? (
          <TraceResult result={state.result} traceAnimationEnabled={traceAnimationEnabled} ngfwServer={ngfwServer} ngfwPort={ngfwPort} />
        ) : (
          <EmptyTraceResult />
        )
      }
    />
  );
}

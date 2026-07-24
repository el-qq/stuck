"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { TraceTargetFields } from "../trace/TraceTargetFields";
import { AccessCompareSideControl } from "./AccessCompareSideControl";
import { AccessCompareView } from "./AccessCompareView";
import type { AccessCompareState } from "./accessCompareState";

interface Props {
  state: AccessCompareState;
  /** NGFW HTTPS port for deep links into the console; absent in the demo. */
  port?: number;
  server?: string;
}

/** Live-only workspace: a shared target plus two independent subject
 * controls (docs/source/comparison.md §4 "Frontend"), and the compare
 * result. Mirrors `SnapshotComparisonWorkspace`'s split between an `aside`
 * input panel and a `section` result. */
export function AccessCompareWorkspace({ state, port, server }: Props) {
  const { t } = useI18n();

  return (
    <main role="tabpanel" id="tabpanel-compare" aria-labelledby="tab-compare" className="hygiene-workspace">
      <aside className="hygiene-workspace__controls">
        <div className="check-panel">
          <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("compare.title")}</div>
          <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 14 }}>{t("compare.subtitle")}</div>

          <TraceTargetFields target={state.target} onSubmit={state.runCompare} />

          <div className="access-compare-sides">
            <AccessCompareSideControl label={t("compare.sideA")} side={state.sideA} />
            <AccessCompareSideControl label={t("compare.sideB")} side={state.sideB} />
          </div>

          <button
            type="button"
            className={`check-submit${state.canSubmit ? " btn-primary" : ""}`}
            onClick={state.runCompare}
            disabled={!state.canSubmit}
            style={{
              width: "100%",
              border: "none",
              borderRadius: "var(--radius-sm)",
              padding: 13,
              fontSize: 14.5,
              fontWeight: 700,
              background: state.canSubmit ? undefined : "var(--skip-soft)",
              color: state.canSubmit ? undefined : "var(--skip)",
              cursor: state.canSubmit ? "pointer" : "not-allowed",
            }}
          >
            {state.submitting ? t("compare.comparing") : t("compare.submit")}
          </button>

          {!state.traceAllowed && <div className="trace-check-panel__notice">{t("access.traceDisabled")}</div>}
          {state.traceAllowed && !state.rulesLoaded && <div className="trace-check-panel__notice">{t("check.noRulesWarning")}</div>}
        </div>
      </aside>

      <section className="hygiene-workspace__result">
        {state.submitting && !state.result && <div className="workspace-loading">{t("compare.resultLoading")}</div>}
        {state.error && !state.submitting && (
          <div role="alert" className="workspace-error">
            {state.error}
          </div>
        )}
        {state.result && !state.error && <AccessCompareView response={state.result} server={server} port={port} />}
        {!state.result && !state.submitting && !state.error && (
          <div className="snapshot-comparison__empty">
            <span aria-hidden="true">⇄</span>
            <div>{t("compare.empty")}</div>
          </div>
        )}
      </section>
    </main>
  );
}

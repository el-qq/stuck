"use client";

import React from "react";
import { useI18n } from "@/i18n";

interface CheckWorkspaceProps {
  controls: React.ReactNode;
  result: React.ReactNode;
  resultRef?: React.Ref<HTMLElement>;
}
/** Shared responsive shell used by both real and offline-demo checks. */
export function CheckWorkspace({ controls, result, resultRef }: CheckWorkspaceProps) {
  return (
    <main className="check-workspace">
      <aside className="check-workspace__controls">{controls}</aside>
      <section ref={resultRef} className="check-workspace__result" aria-live="polite">
        {result}
      </section>
    </main>
  );
}

export function EmptyTraceResult() {
  const { t } = useI18n();

  return (
    <div className="empty-trace-result">
      <div className="empty-trace-result__icon" aria-hidden="true">
        →
      </div>
      <div className="empty-trace-result__title">{t("check.emptyTitle")}</div>
      <div className="empty-trace-result__subtitle">{t("check.emptySubtitle")}</div>
    </div>
  );
}

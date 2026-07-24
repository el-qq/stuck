"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { CompareResponse } from "@/lib/types";
import { AccessCompareView } from "./AccessCompareView";

interface Props {
  response: CompareResponse;
}

/** Demo-only workspace (docs/source/comparison.md §4 "Демо"): unlike the live
 * `AccessCompareWorkspace`, the aside has no interactive subject pickers —
 * the two illustrative subjects are fixed (`lib/demoData.ts`). It renders
 * the exact same `AccessCompareView` the live tab does, with no server/port
 * so no NGFW console deep link is offered for a static example. */
export function AccessCompareDemoWorkspace({ response }: Props) {
  const { t } = useI18n();

  return (
    <main role="tabpanel" id="tabpanel-compare" aria-labelledby="tab-compare" className="hygiene-workspace">
      <aside className="hygiene-workspace__controls">
        <div className="check-panel">
          <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("compare.title")}</div>
          <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5 }}>{t("compare.subtitle")}</div>
          <div className="demo-unavailable-hint" style={{ marginTop: 14 }}>
            {t("demo.backendActionsUnavailable")}
          </div>
        </div>
      </aside>
      <section className="hygiene-workspace__result">
        <AccessCompareView response={response} />
      </section>
    </main>
  );
}

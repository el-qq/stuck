"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { STAGE_ORDER } from "@/lib/types";

/**
 * The "processing order" reference block under the check form: a short
 * first-match hint and the pipeline stages in a COLUMN (name, ↓, name…).
 * Derived from STAGE_ORDER, so new stages (e.g. hardware filtering) appear
 * automatically and stay in sync with the contract.
 *
 * Collapsible and COLLAPSED by default — it is reference material, not part
 * of the check flow.
 */
export function PipelineOrder() {
  const { t } = useI18n();
  return (
    <details className="pipeline-order">
      <summary>{t("check.orderTitle")}</summary>
      <div className="pipeline-order__body">
        <div style={{ marginBottom: 10 }}>{t("check.orderText")}</div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 2 }}>
          {STAGE_ORDER.map((key, i) => (
            <React.Fragment key={key}>
              {i > 0 && (
                <span aria-hidden="true" style={{ color: "var(--skip)", lineHeight: 1, paddingLeft: 6 }}>
                  ↓
                </span>
              )}
              <span>{t(`stage.${key}` as MessageKey)}</span>
            </React.Fragment>
          ))}
        </div>
      </div>
    </details>
  );
}

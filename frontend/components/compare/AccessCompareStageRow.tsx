"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { ngfwRuleSectionUrl } from "@/lib/ngfwRuleLink";
import { STATUS_TONE } from "@/lib/stages";
import { CompareStage, StageKey, TraceStage } from "@/lib/types";
import { CLASSIFICATION_TONE } from "./accessComparePresentation";

interface RowProps {
  stage: CompareStage;
  primary: boolean;
  server?: string;
  port?: number;
}

/** One pipeline stage, side A and side B rendered side by side. The row's
 * border/background encodes the DIFF classification (same/divergent/
 * incomparable); each mini-card inside keeps its own stage-status tone from
 * `lib/stages.ts` — the two colorings answer different questions and must
 * stay visually distinct (honesty: `incomparable` must never read as a
 * proven `divergent`, invariant №7). */
export function AccessCompareStageRow({ stage, primary, server, port }: RowProps) {
  const { t, tOptional } = useI18n();
  const title = tOptional(stage.title_key) ?? t(`stage.${stage.key}` as MessageKey);
  const tone = CLASSIFICATION_TONE[stage.classification];

  return (
    <div className="access-compare__row" data-tone={tone} data-primary={primary ? "true" : undefined}>
      <div className="access-compare__row-label">
        <span>{title}</span>
        <span className="access-compare__row-tags">
          {stage.classification === "divergent" && stage.divergence_kind === "same_status_different_rule" && (
            <span className="access-compare__tag">{t("compare.differentRuleTag")}</span>
          )}
          {primary && <span className="access-compare__tag access-compare__tag--primary">{t("compare.primaryTag")}</span>}
        </span>
      </div>
      <AccessCompareMiniStage stage={stage.a} stageKey={stage.key} blocking={stage.blocking_side === "a"} server={server} port={port} />
      <AccessCompareMiniStage stage={stage.b} stageKey={stage.key} blocking={stage.blocking_side === "b"} server={server} port={port} />
    </div>
  );
}

interface MiniProps {
  stage: TraceStage;
  stageKey: StageKey;
  blocking: boolean;
  server?: string;
  port?: number;
}

function AccessCompareMiniStage({ stage, stageKey, blocking, server, port }: MiniProps) {
  const { t, tOptional } = useI18n();
  const statusTone = STATUS_TONE[stage.status];
  const detail = stage.detail;
  const reasonText = detail?.reason_key ? tOptional(`reason.${detail.reason_key}`) : null;
  const ruleLabel = detail?.rule_name ?? detail?.rule_id ?? null;
  const ruleUrl = ngfwRuleSectionUrl(server, port, stageKey, detail?.rule_id);

  return (
    <div className="access-compare__mini-stage" data-status-tone={statusTone} data-blocking={blocking ? "true" : undefined}>
      <span className="access-compare__mini-status">{t(`status.${stage.status}` as MessageKey)}</span>
      {ruleLabel && (
        <span className="access-compare__mini-rule mono breakable">
          {ruleLabel}
          {detail?.rule_name && detail?.rule_id && <span className="access-compare__mini-rule-id"> (id={detail.rule_id})</span>}
          {ruleUrl && (
            <a href={ruleUrl} target="_blank" rel="noopener noreferrer" className="link-btn access-compare__mini-link">
              {t("common.openNgfwSection")} ↗
            </a>
          )}
        </span>
      )}
      {!ruleLabel && reasonText && <span className="access-compare__mini-reason">{reasonText}</span>}
      {!ruleLabel && !reasonText && <span className="access-compare__mini-reason">{t("detail.noRule")}</span>}
    </div>
  );
}

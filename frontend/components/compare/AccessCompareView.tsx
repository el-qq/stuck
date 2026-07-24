"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { CompareResponse } from "@/lib/types";
import { protocolDisplayLabel } from "@/lib/protocol";
import { compareSubjectLabel } from "./accessComparePresentation";
import { AccessCompareStageRow } from "./AccessCompareStageRow";

interface Props {
  response: CompareResponse;
  /** Live workspace supplies these for an NGFW console deep link. The
   * offline demo deliberately omits them — a static example must not point
   * to an administrator's local appliance (mirrors `StageNode`/`TraceResult`). */
  server?: string;
  port?: number;
}

const VERDICT_TITLE_KEY: Record<string, MessageKey> = {
  allowed: "verdict.allowedTitle",
  blocked: "verdict.blockedTitle",
  conditional: "verdict.conditionalTitle",
  partial: "verdict.partialTitle",
  unknown: "verdict.unknownTitle",
};

/**
 * Presentational access-compare result, shared by the live and demo
 * workspaces (docs/source/comparison.md §4). Renders ONLY React text nodes —
 * server-controlled strings never become HTML. Static in v1 (decision §5.5):
 * both columns render at once, no lockstep stage-reveal animation.
 */
export function AccessCompareView({ response, server, port }: Props) {
  const { t, tOptional } = useI18n();
  // Same visual order as the single-trace result (TraceResult): the pipeline
  // reads bottom-up, so the destination end (final availability) is on top and
  // hardware filtering is at the bottom. `primary_divergence` is keyed by
  // stage id, so display order does not affect which stage is highlighted.
  const stages = [...response.stages].sort((a, b) => b.order - a.order);
  const contextMismatch = response.a.context.has_source_ip !== response.b.context.has_source_ip;
  const primaryStageTitle = response.primary_divergence ? (tOptional(`stage.${response.primary_divergence}`) ?? response.primary_divergence) : null;

  return (
    <div className="access-compare">
      <div className="access-compare__subjects">
        <AccessCompareSubjectHeader label={t("compare.sideA")} response={response} side="a" />
        <AccessCompareSubjectHeader label={t("compare.sideB")} response={response} side="b" />
      </div>

      <div className="access-compare__target mono breakable">
        {t("verdict.targetLabel")}: {response.a.target.normalized_url} · {protocolDisplayLabel(response.target_input.protocol, t)}
        {response.target_input.dst_port ? `:${response.target_input.dst_port}` : ""}
      </div>

      {response.categories.length > 0 && (
        <div className="access-compare__categories">
          {response.categories.map((category) => (
            <span key={category} className="access-compare__category breakable">
              {category}
            </span>
          ))}
        </div>
      )}

      {response.identical_subjects && <div className="access-compare__banner access-compare__banner--ok">{t("compare.identicalSubjectsBanner")}</div>}
      {!response.identical_subjects && contextMismatch && (
        <div className="access-compare__banner access-compare__banner--info">{t("compare.contextMismatchBanner")}</div>
      )}
      {response.divergence_reason === "context_incomplete" && (
        <div className="access-compare__banner access-compare__banner--warn">{t("compare.contextIncompleteBanner")}</div>
      )}
      {response.divergence_reason === "diverged" && primaryStageTitle && (
        <div className="access-compare__banner access-compare__banner--bad">{t("compare.primaryDivergenceBanner", { stage: primaryStageTitle })}</div>
      )}
      {response.divergence_reason === null && !response.identical_subjects && (
        <div className="access-compare__banner access-compare__banner--ok">{t("compare.noStageDifferencesBanner")}</div>
      )}

      <div className="access-compare__rows">
        {stages.map((stage) => (
          <AccessCompareStageRow key={stage.key} stage={stage} primary={stage.key === response.primary_divergence} server={server} port={port} />
        ))}
      </div>

      <div className="access-compare__legend">{t("compare.legendHint")}</div>
    </div>
  );
}

function AccessCompareSubjectHeader({ label, response, side }: { label: string; response: CompareResponse; side: "a" | "b" }) {
  const { t } = useI18n();
  const compareSide = response[side];
  const verdict = compareSide.summary.verdict;
  const verdictKey = VERDICT_TITLE_KEY[verdict] ?? VERDICT_TITLE_KEY.unknown!;

  return (
    <div className="access-compare__subject" data-verdict={verdict}>
      <div className="access-compare__subject-side">{label}</div>
      <div className="access-compare__subject-name breakable">{compareSubjectLabel(compareSide, t)}</div>
      <div className="access-compare__subject-verdict">{t(verdictKey)}</div>
    </div>
  );
}

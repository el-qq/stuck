"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { TraceResponse } from "@/lib/types";
import { useStageReveal } from "@/hooks/useStageReveal";
import { usePublicConfig } from "@/contexts/PublicConfigContext";
import { StageNode } from "./StageNode";

export function TraceResult({ result }: { result: TraceResponse }) {
  const { t, tOptional } = useI18n();
  const { traceAnimationEnabled } = usePublicConfig();
  const { revealCount, flowing, done, skip, animateStages } = useStageReveal(result.stages, traceAnimationEnabled);

  const stages = [...result.stages].sort((a, b) => a.order - b.order);
  // Iteration 3 (#7): the pipeline renders bottom-up — newly revealed stages
  // appear on top, so after the animation the verdict ends up first (topmost).
  const displayStages = [...stages].reverse();
  const verdict = result.summary.verdict;

  const blockedStage = result.summary.blocked_at ? stages.find((s) => s.key === result.summary.blocked_at) : undefined;
  const blockedStageTitle = blockedStage ? (tOptional(blockedStage.title_key) ?? t(`stage.${blockedStage.key}` as MessageKey)) : "";
  const blockedRule = blockedStage?.detail?.rule_name ?? blockedStage?.detail?.rule_id ?? null;

  const verdictMeta: Record<string, { icon: string; title: string; sub: string; c: string; s: string }> = {
    allowed: {
      icon: "✓",
      title: t("verdict.allowedTitle"),
      sub: t("verdict.allowedSub"),
      c: "var(--ok)",
      s: "var(--ok-soft)",
    },
    blocked: {
      icon: "✕",
      title: t("verdict.blockedTitle"),
      sub: blockedRule
        ? t("verdict.blockedSubWithRule", { stage: blockedStageTitle, rule: blockedRule })
        : t("verdict.blockedSubNoRule", { stage: blockedStageTitle }),
      c: "var(--bad)",
      s: "var(--bad-soft)",
    },
    conditional: {
      icon: "i",
      title: t("verdict.conditionalTitle"),
      sub: t("verdict.conditionalSub"),
      c: "var(--info)",
      s: "var(--info-soft)",
    },
    partial: {
      icon: "◐",
      title: t("verdict.partialTitle"),
      sub: t("verdict.partialSub"),
      c: "var(--warn)",
      s: "var(--warn-soft)",
    },
    unknown: {
      icon: "?",
      title: t("verdict.unknownTitle"),
      sub: t("verdict.unknownSub"),
      c: "var(--skip)",
      s: "var(--skip-soft)",
    },
  };
  const v = verdictMeta[verdict] ?? verdictMeta.unknown!;

  return (
    <div className="trace-result">
      <div className="trace-result__header">
        <div className="trace-result__host mono breakable" style={{ fontSize: 18, fontWeight: 700 }}>
          {result.target.host}
        </div>
        <div className="breakable" style={{ fontSize: 13, color: "var(--muted)" }}>
          {result.user ? t("check.resultAsUser", { name: result.user.name, login: result.user.login }) : t("check.resultAllUsers")}
        </div>
        {result.target.resolved_ip && (
          <div className="mono breakable" style={{ fontSize: 12, color: "var(--muted)" }}>
            {t("verdict.resolvedIpLabel")}: {result.target.resolved_ip}
          </div>
        )}
        {result.target.source_ip && (
          <div className="mono breakable" style={{ fontSize: 12, color: "var(--muted)" }}>
            {t("verdict.sourceIpLabel")}: {result.target.source_ip}
          </div>
        )}
        <div style={{ flex: 1 }} />
        {/* Iteration 3 (#6): "replay animation" removed; "skip" stays. */}
        {traceAnimationEnabled && !done && (
          <button className="link-btn" onClick={skip} style={{ fontSize: 12.5, fontWeight: 600 }}>
            {t("verdict.skipAnimation")}
          </button>
        )}
      </div>

      {result.categories.length > 0 && (
        <div className="trace-result__categories">
          <span style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)" }}>{t("verdict.categoriesLabel")}:</span>
          {result.categories.map((cat) => (
            <span
              key={cat}
              className="breakable"
              style={{
                fontSize: 12,
                color: "var(--accent)",
                background: "var(--accent-soft)",
                borderRadius: 999,
                padding: "3px 10px",
                fontWeight: 600,
              }}
            >
              {cat}
            </span>
          ))}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column" }}>
        {/* Iteration 3 (#7): the final verdict card sits ABOVE the stage list. */}
        <div
          className="trace-verdict"
          style={{
            display: "flex",
            gap: 4,
            marginBottom: 14,
            opacity: done ? 1 : 0,
            transform: done ? "translateY(0)" : "translateY(-14px)",
            transition: "opacity .5s ease, transform .5s ease",
          }}
        >
          <div className="trace-pipeline__rail">
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: "50%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 17,
                fontWeight: 700,
                color: "#fff",
                background: v.c,
                border: "3px solid var(--bg)",
                boxShadow: "var(--shadow)",
              }}
            >
              {v.icon}
            </div>
          </div>
          <div
            className="trace-verdict__card"
            style={{
              flex: 1,
              borderRadius: "var(--radius-md)",
              padding: "20px 24px",
              background: v.s,
              border: `1px solid ${v.c}`,
              color: "var(--text)",
            }}
          >
            <div style={{ fontSize: 17, fontWeight: 700 }}>{v.title}</div>
            <div style={{ fontSize: 13.5, marginTop: 6, opacity: 0.85, lineHeight: 1.5 }}>{v.sub}</div>
            <div className="trace-result__target mono breakable" style={{ fontSize: 12, marginTop: 10, opacity: 0.7 }}>
              {t("verdict.targetLabel")}: {result.target.normalized_url} · {result.target.protocol.toUpperCase()}:{result.target.dst_port}
            </div>
          </div>
        </div>

        {/* Stages in reverse traffic order: each newly revealed stage mounts
            on TOP and pushes the earlier ones down (bottom-up pipeline). */}
        {displayStages.map((stage, di) => {
          const trafficIndex = stages.length - 1 - di;
          if (!(trafficIndex < revealCount || done)) return null;
          return (
            <StageNode
              key={stage.key}
              stage={stage}
              isLast={trafficIndex === 0}
              revealed
              animate={animateStages}
              flowingConnector={flowing && trafficIndex === revealCount - 1}
            />
          );
        })}
      </div>
    </div>
  );
}

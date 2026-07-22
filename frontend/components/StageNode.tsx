"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { useSession } from "@/contexts/SessionContext";
import { MessageKey } from "@/i18n/en";
import { TraceStage } from "@/lib/types";
import { ngfwRuleSectionUrl } from "@/lib/ngfwRuleLink";
import { STAGE_ABBR, STATUS_TONE } from "@/lib/stages";

const TONE_COLOR: Record<string, string> = {
  ok: "var(--ok)",
  bad: "var(--bad)",
  warn: "var(--warn)",
  info: "var(--info)",
  skip: "var(--skip)",
};
const TONE_SOFT: Record<string, string> = {
  ok: "var(--ok-soft)",
  bad: "var(--bad-soft)",
  warn: "var(--warn-soft)",
  info: "var(--info-soft)",
  skip: "var(--skip-soft)",
};

interface Props {
  stage: TraceStage;
  isLast: boolean;
  revealed: boolean;
  animate: boolean;
  flowingConnector: boolean;
}

export function StageNode({ stage, isLast, revealed, animate, flowingConnector }: Props) {
  const { t, tOptional } = useI18n();
  const session = useSession();

  const tone = STATUS_TONE[stage.status];
  const color = TONE_COLOR[tone];
  const soft = TONE_SOFT[tone];
  const title = tOptional(stage.title_key) ?? t(`stage.${stage.key}` as MessageKey);
  const detail = stage.detail;
  const ngfwRuleUrl = ngfwRuleSectionUrl(session.session?.server, session.session?.ngfw_port, stage.key, detail?.rule_id);
  const reasonText = detail?.reason_key ? tOptional(`reason.${detail.reason_key}`) : null;

  const detailRows: { k: string; v: string }[] = [];
  if (detail?.action) detailRows.push({ k: t("detail.action"), v: detail.action });
  if (detail?.matched_category) detailRows.push({ k: t("detail.category"), v: detail.matched_category });
  if (detail?.redirect_url) detailRows.push({ k: t("detail.redirect"), v: detail.redirect_url });
  if (detail?.speed_kbps !== undefined) detailRows.push({ k: t("detail.speedLimit"), v: `${detail.speed_kbps} ${t("detail.kbps")}` });
  if (detail?.limit_scope)
    detailRows.push({
      k: t("detail.limitScope"),
      v: detail.limit_scope === "user" ? t("detail.scopeUser") : detail.limit_scope === "group" ? t("detail.scopeGroup") : detail.limit_scope,
    });
  if (detail?.hw_mode) detailRows.push({ k: t("detail.hwMode"), v: detail.hw_mode });
  if (detail?.resolved_ip) detailRows.push({ k: t("detail.resolvedIp"), v: detail.resolved_ip });
  if (detail?.firewall_table) detailRows.push({ k: t("detail.firewallTable"), v: detail.firewall_table.toUpperCase() });
  if (detail?.translated_destination_ip)
    detailRows.push({
      k: t("detail.translatedDestination"),
      v: `${detail.translated_destination_ip}${detail.translated_destination_port ? `:${detail.translated_destination_port}` : ""}`,
    });
  if (detail?.translated_source_ip) detailRows.push({ k: t("detail.translatedSource"), v: detail.translated_source_ip });
  if (detail?.module_enabled !== undefined) detailRows.push({ k: t("detail.module"), v: detail.module_enabled ? t("detail.moduleOn") : t("detail.moduleOff") });

  const hasRuleBox = !!(detail && (detail.rule_name || detail.rule_id || detailRows.length > 0));

  // Iteration 3 (#7): stages mount one by one on TOP of the list (bottom-up
  // pipeline), so the entrance animation plays on mount; unrevealed stages
  // are simply not rendered by the parent.
  return (
    <div
      className="stage-node"
      aria-hidden={!revealed}
      style={{
        display: "flex",
        gap: 4,
        opacity: revealed ? undefined : 0,
        animation: revealed && animate ? "fadeDown .45s ease both" : undefined,
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
            fontSize: 10.5,
            fontWeight: 700,
            color: tone === "skip" ? "var(--muted)" : "#fff",
            background: tone === "skip" ? "var(--skip-soft)" : color,
            border: "3px solid var(--bg)",
            boxShadow: "var(--shadow)",
            flexShrink: 0,
            position: "relative",
            zIndex: 1,
          }}
        >
          {STAGE_ABBR[stage.key]}
        </div>
        {!isLast && (
          <div style={{ position: "relative", width: 2, flex: 1, minHeight: 24, background: "var(--line)" }}>
            {flowingConnector && (
              <span
                style={{
                  position: "absolute",
                  left: -3,
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: "var(--accent)",
                  boxShadow: "0 0 8px var(--accent)",
                  animation: "flowDotUp .42s linear infinite",
                }}
              />
            )}
          </div>
        )}
      </div>
      <div
        className="stage-node__card"
        style={{
          flex: 1,
          background: "var(--panel)",
          border: "1px solid var(--line)",
          borderRadius: "var(--radius-md)",
          boxShadow: "var(--shadow)",
          padding: "16px 20px",
          marginBottom: 14,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div style={{ fontSize: 14.5, fontWeight: 700 }}>{title}</div>
          <div
            style={{
              fontSize: 12,
              fontWeight: 700,
              color,
              background: soft,
              borderRadius: 999,
              padding: "4px 11px",
            }}
          >
            {t(`status.${stage.status}` as MessageKey)}
          </div>
        </div>

        {reasonText && <div style={{ fontSize: 13, color: "var(--muted)", marginTop: 8, lineHeight: 1.5 }}>{reasonText}</div>}
        {!reasonText && !hasRuleBox && <div style={{ fontSize: 13, color: "var(--muted)", marginTop: 8, lineHeight: 1.5 }}>{t("detail.noRule")}</div>}

        {hasRuleBox && (
          <div
            style={{
              marginTop: 12,
              background: "var(--panel2)",
              border: "1px solid var(--line)",
              borderRadius: "var(--radius-sm)",
              padding: "12px 14px",
            }}
          >
            {(detail?.rule_name || detail?.rule_id) && (
              <div className="stage-node__rule" style={{ marginBottom: detailRows.length ? 8 : 0 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: "var(--muted)", letterSpacing: "0.06em" }}>{t("detail.ruleTriggered").toUpperCase()}</span>
                <span className="mono breakable" style={{ fontSize: 13.5, fontWeight: 700 }}>
                  {detail?.rule_name ?? detail?.rule_id}
                  {detail?.rule_name && detail?.rule_id && (
                    // The id is shown explicitly next to the name so the rule
                    // can be found in the NGFW console unambiguously.
                    <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--muted)" }}> (id={detail.rule_id})</span>
                  )}
                </span>
                {ngfwRuleUrl && (
                  <a
                    href={ngfwRuleUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="link-btn"
                    style={{ alignSelf: "flex-start", fontSize: 12.5, fontWeight: 600 }}
                  >
                    {t("common.openNgfwSection")} ↗
                  </a>
                )}
              </div>
            )}
            {detailRows.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "8px 16px" }}>
                {detailRows.map((row) => (
                  <div key={row.k} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                    <span style={{ fontSize: 11, color: "var(--muted)", fontWeight: 600 }}>{row.k}</span>
                    <span className="breakable" style={{ fontSize: 12.5, fontWeight: 600 }}>
                      {row.v}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

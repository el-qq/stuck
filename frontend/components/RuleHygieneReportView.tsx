"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { ngfwRuleSectionUrl } from "@/lib/ngfwRuleLink";
import { HygieneFinding, HygieneSeverity, HygieneSummary, RuleHygieneReport } from "@/lib/types";

const SEVERITY_ORDER: HygieneSeverity[] = ["risk", "warning", "info"];

export const SEVERITY_COLOR: Record<HygieneSeverity, string> = {
  risk: "var(--bad)",
  warning: "var(--warn)",
  info: "var(--info)",
};

const TABLES = ["fw_forward", "fw_input"] as const;
export type HygieneTable = (typeof TABLES)[number];

interface Props {
  report: RuleHygieneReport;
  /** NGFW HTTPS port for per-finding deep links; absent (demo) hides them. */
  port?: number;
  /** Constrain the findings list and scroll inside it (modal); unset lets the
   *  page scroll naturally (full-width tab). */
  listMaxHeight?: string;
  /** Hide the severity counters when the surrounding layout renders them
   *  itself (the demo tab shows them in the left panel). */
  showCounters?: boolean;
  /** Show only one firewall chain (left-panel section navigation). */
  filterTable?: HygieneTable | null;
}

/** Tab badge takes the color of the worst present severity. */
export function hygieneBadgeColor(summary: Pick<HygieneSummary, "risk" | "warning">): string {
  if (summary.risk > 0) return SEVERITY_COLOR.risk;
  if (summary.warning > 0) return SEVERITY_COLOR.warning;
  return SEVERITY_COLOR.info;
}

/** Severity counters row — also reused by the demo tab's left panel. */
export function HygieneCounters({ summary }: { summary: HygieneSummary }) {
  const { t } = useI18n();
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      <Counter color={SEVERITY_COLOR.risk} label={t("hygiene.countsRisk", { count: summary.risk })} />
      <Counter color={SEVERITY_COLOR.warning} label={t("hygiene.countsWarning", { count: summary.warning })} />
      <Counter color={SEVERITY_COLOR.info} label={t("hygiene.countsInfo", { count: summary.info })} />
    </div>
  );
}

/** Presentational findings tree of a rule-hygiene report, grouped by firewall
 *  chain. Shared by the modal (live) and the demo workspace tab. */
export function RuleHygieneReportView({ report, port, listMaxHeight, showCounters = true, filterTable = null }: Props) {
  const { t } = useI18n();

  const groups = TABLES.filter((table) => !filterTable || table === filterTable)
    .map((table) => ({ table, findings: sortFindings(report.findings.filter((f) => f.table === table)) }))
    .filter((g) => g.findings.length > 0);

  if (report.summary.total === 0 || groups.length === 0) {
    return (
      <div
        style={{
          fontSize: 13.5,
          color: "var(--ok)",
          background: "var(--ok-soft)",
          borderRadius: "var(--radius-sm)",
          padding: "14px 16px",
          lineHeight: 1.5,
        }}
      >
        ✓ {t("hygiene.clean")}
      </div>
    );
  }

  return (
    <>
      {showCounters && (
        <div style={{ marginBottom: 14 }}>
          <HygieneCounters summary={report.summary} />
        </div>
      )}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 12,
          ...(listMaxHeight ? { maxHeight: listMaxHeight, overflowY: "auto" } : {}),
        }}
      >
        {groups.map((g) => (
          <details className="hygiene-group" open key={g.table}>
            <summary>
              {t("hygiene.sectionFirewall")} · {t(g.table === "fw_forward" ? "hygiene.tableForward" : "hygiene.tableInput")}
              <span className="hygiene-group__count">{g.findings.length}</span>
            </summary>
            <div className="hygiene-group__body">
              {g.findings.map((f, i) => (
                <FindingRow key={`${f.rule.id}-${f.kind}-${i}`} finding={f} server={report.binding.server} port={port} />
              ))}
            </div>
          </details>
        ))}
      </div>
    </>
  );
}

function Counter({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12.5, fontWeight: 600 }}>
      <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
      {label}
    </span>
  );
}

function FindingRow({ finding, server, port }: { finding: HygieneFinding; server: string; port?: number }) {
  const { t } = useI18n();
  const color = SEVERITY_COLOR[finding.severity];
  const link = ngfwRuleSectionUrl(server, port, "firewall", finding.rule.id);
  const coverer = finding.related[0];

  return (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        background: "var(--panel2)",
        borderRadius: "var(--radius-sm)",
        padding: "11px 13px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13.5, fontWeight: 700, color }}>{kindLabel(t, finding.kind)}</span>
        <span className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
          {t("hygiene.rule", { position: finding.rule.position })} · id={finding.rule.id}
          {link ? " ·" : ""}
        </span>
        {link && (
          <a href={link} target="_blank" rel="noopener noreferrer" style={{ fontSize: 11.5, fontWeight: 600, color: "var(--accent)" }}>
            {t("common.openNgfwSection")} ↗
          </a>
        )}
        {finding.tier === "possible" && (
          <span
            title={t("hygiene.possibleHint")}
            style={{ fontSize: 10.5, fontWeight: 700, color: "var(--muted)", border: "1px solid var(--line)", borderRadius: 4, padding: "1px 5px" }}
          >
            {t("hygiene.possibleBadge")}
          </span>
        )}
      </div>
      {finding.rule.name && (
        <div
          title={finding.rule.name}
          style={{
            fontSize: 12.5,
            fontWeight: 600,
            // 60% alpha of the text color: a step above the muted meta only.
            color: "color-mix(in srgb, var(--text) 60%, transparent)",
            // Extra breathing room before the explanation block below.
            margin: "4px 0 7px",
            // Long names must not escape the card — ellipsis + full-name tooltip.
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            maxWidth: "100%",
          }}
        >
          «{finding.rule.name}»
        </div>
      )}
      <div style={{ fontSize: 12.5, color: "var(--text)", lineHeight: 1.5, marginTop: finding.rule.name ? 0 : 4 }}>{explain(t, finding, coverer)}</div>
    </div>
  );
}

type TFn = ReturnType<typeof useI18n>["t"];

function kindLabel(t: TFn, kind: HygieneFinding["kind"]): string {
  switch (kind) {
    case "shadowed":
      return t("hygiene.kindShadowed");
    case "redundant":
      return t("hygiene.kindRedundant");
    case "unreachable_after_any":
      return t("hygiene.kindUnreachable");
    case "overly_broad":
      return t("hygiene.kindOverlyBroad");
  }
}

function explain(t: TFn, f: HygieneFinding, coverer?: HygieneFinding["related"][number]): string {
  switch (f.kind) {
    case "shadowed":
      return t("hygiene.explainShadowed", { position: coverer?.position ?? "?" });
    case "redundant":
      return t("hygiene.explainRedundant", { position: coverer?.position ?? "?" });
    case "unreachable_after_any":
      return t("hygiene.explainUnreachable", { position: f.rule.position, count: f.extra?.unreachable_count ?? f.related.length });
    case "overly_broad":
      // The backend grades the same kind by context: first rule → risk (all
      // traffic allowed), after drops → info (deliberate tail), else warning.
      if (f.severity === "risk") return t("hygiene.explainOverlyBroadFirst");
      if (f.severity === "info") return t("hygiene.explainOverlyBroadTail");
      return t("hygiene.explainOverlyBroad");
  }
}

/** Risk → warning → info, then by position for a stable reading order. */
function sortFindings(findings: HygieneFinding[]): HygieneFinding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.rule.position - b.rule.position);
}

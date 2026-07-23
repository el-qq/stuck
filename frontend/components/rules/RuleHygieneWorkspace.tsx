"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { RuleHygieneReport } from "@/lib/types";
import { HygieneCounters, HygieneTable, RuleHygieneReportView } from "./RuleHygieneReportView";

interface Props {
  report: RuleHygieneReport | null;
  loading: boolean;
  error: string | null;
  section: "all" | HygieneTable;
  onSectionChange: (section: "all" | HygieneTable) => void;
  onRecheck?: () => void;
  /** Demos retain the control's layout but must never invoke backend refresh. */
  backendActionsUnavailable?: boolean;
  port?: number;
}

/** Shared hygiene tab for live and demo workspaces. The report stays a pure
 * input; only the live adapter supplies a re-check action. */
export function RuleHygieneWorkspace({ report, loading, error, section, onSectionChange, onRecheck, backendActionsUnavailable = false, port }: Props) {
  const { t, locale } = useI18n();
  const sectionCount = (table: HygieneTable) => report?.findings.filter((finding) => finding.table === table).length ?? 0;

  return (
    <main role="tabpanel" id="tabpanel-hygiene" aria-labelledby="tab-hygiene" className="hygiene-workspace">
      <aside className="hygiene-workspace__controls">
        <div className="check-panel">
          <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("hygiene.title")}</div>
          {report && (
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 14 }}>
              {t("hygiene.updated", { time: formatTime(report.rules_updated_at, locale) })}
            </div>
          )}

          <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 10 }}>{t("hygiene.subtitle")}</div>
          {report && (
            <>
              <HygieneCounters summary={report.summary} />

              <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />

              <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)", marginBottom: 8 }}>{t("hygiene.sections")}</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <button className="hygiene-nav__item" aria-pressed={section === "all"} onClick={() => onSectionChange("all")}>
                  {t("hygiene.sectionAll")}
                  <span className="hygiene-nav__count">{report.summary.total}</span>
                </button>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", margin: "6px 0 2px" }}>{t("hygiene.sectionFirewall")}</div>
                <button
                  className="hygiene-nav__item hygiene-nav__item--child"
                  aria-pressed={section === "fw_forward"}
                  onClick={() => onSectionChange("fw_forward")}
                >
                  {t("hygiene.tableForward")}
                  <span className="hygiene-nav__count">{sectionCount("fw_forward")}</span>
                </button>
                <button
                  className="hygiene-nav__item hygiene-nav__item--child"
                  aria-pressed={section === "fw_input"}
                  onClick={() => onSectionChange("fw_input")}
                >
                  {t("hygiene.tableInput")}
                  <span className="hygiene-nav__count">{sectionCount("fw_input")}</span>
                </button>
                <button
                  className="hygiene-nav__item"
                  style={{ marginTop: 6 }}
                  aria-pressed={section === "hw_filter"}
                  onClick={() => onSectionChange("hw_filter")}
                >
                  {t("stage.hw_filter")}
                  <span className="hygiene-nav__count">{sectionCount("hw_filter")}</span>
                </button>
              </div>

              <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />
            </>
          )}

          <button
            type="button"
            className="btn-primary"
            onClick={backendActionsUnavailable ? undefined : onRecheck}
            disabled={backendActionsUnavailable || loading}
            title={backendActionsUnavailable ? t("demo.backendActionUnavailable") : undefined}
            data-demo-unavailable={backendActionsUnavailable || undefined}
            style={{ width: "100%", border: "none", borderRadius: "var(--radius-sm)", padding: 11, fontSize: 13.5, fontWeight: 700 }}
          >
            {loading ? t("hygiene.rechecking") : t("hygiene.recheck")}
          </button>
          {backendActionsUnavailable && <p className="demo-unavailable-hint">{t("demo.backendActionsUnavailable")}</p>}
        </div>
      </aside>
      <section className="hygiene-workspace__result">
        {loading && !report && <div className="workspace-loading">{t("hygiene.loading")}</div>}
        {error && !loading && (
          <div role="alert" className="workspace-error">
            {error}
          </div>
        )}
        {report && !error && <RuleHygieneReportView report={report} port={port} showCounters={false} filterTable={section === "all" ? null : section} />}
      </section>
    </main>
  );
}

function formatTime(iso: string, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "medium" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

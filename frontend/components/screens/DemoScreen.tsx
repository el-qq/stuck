"use client";

import React, { useRef, useState } from "react";
import { useI18n } from "@/i18n";
import { PipelineOrder } from "../trace/PipelineOrder";
import { DomainType, TraceResponse } from "@/lib/types";
import { DEMO_HYGIENE_REPORT, DEMO_TARGETS, DEFAULT_DEMO_TARGET, DEMO_USERS, runDemoTrace } from "@/lib/demoData";
import { SERVICE_PRESETS } from "@/lib/servicePresets";
import { HygieneCounters, HygieneTable, RuleHygieneReportView, hygieneBadgeColor } from "../rules/RuleHygieneReportView";
import { Header } from "../shell/Header";
import { SettingsModal } from "../shell/SettingsModal";
import { WorkspaceTabs } from "../shell/WorkspaceTabs";
import { CheckWorkspace, EmptyTraceResult } from "../trace/CheckWorkspace";
import { TraceResult } from "../trace/TraceResult";
import { UserPicker } from "../trace/UserPicker";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";

/**
 * Iteration 4/5: fully offline demo. Same check screen as the real app, but the
 * address field is read-only and the target is picked from two demo targets
 * shown in the "recent addresses" block. The trace is computed locally by the
 * demo engine (lib/demoData.ts) — no backend, no /api/* calls.
 */
export function DemoScreen({ onExit }: { onExit: () => void }) {
  const { t, locale } = useI18n();

  const [settingsOpen, setSettingsOpen] = useState(false);
  // Top-level workspace tab: the traffic check or the offline rule-hygiene
  // showcase (lib/demoData.ts) — no /api/* calls either way.
  const [tab, setTab] = useState<"check" | "hygiene">("check");
  // Left-panel section navigation of the hygiene tab: all chains or one chain.
  const [hygieneSection, setHygieneSection] = useState<"all" | HygieneTable>("all");
  const [mode, setMode] = useState<"all" | "user">("all");
  const [userQuery, setUserQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState<"all" | DomainType>("all");
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  // Iteration 5 #3: success.com:443 selected by default.
  const [targetAddress, setTargetAddress] = useState(DEFAULT_DEMO_TARGET.address);
  const [result, setResult] = useState<TraceResponse | null>(null);
  // Re-mount TraceResult on each run so the reveal animation restarts.
  const [runKey, setRunKey] = useState(0);
  const resultRef = useRef<HTMLElement>(null);
  useMobileResultScroll(resultRef, runKey);

  const selectedUser = DEMO_USERS.find((u) => u.id === selectedUserId) ?? null;
  const selectedTarget = DEMO_TARGETS.find((d) => d.address === targetAddress) ?? DEFAULT_DEMO_TARGET;
  const canCheck = mode === "all" || !!selectedUser;

  function handleCheck() {
    if (!canCheck) return;
    const user = mode === "user" ? selectedUser : null;
    setResult(runDemoTrace(selectedTarget, user, t));
    setRunKey((k) => k + 1);
  }

  // Top-level sections. The bar itself is sticky under the header
  // (WorkspaceTabs), so scrolling the results never hides the tabs.
  const workspaceTabs = (
    <WorkspaceTabs ariaLabel={t("tabs.aria")}>
      <button
        role="tab"
        id="tab-check"
        aria-selected={tab === "check"}
        aria-controls="tabpanel-check"
        className="workspace-tabs__tab"
        onClick={() => setTab("check")}
      >
        {t("tabs.check")}
      </button>
      <button
        role="tab"
        id="tab-hygiene"
        aria-selected={tab === "hygiene"}
        aria-controls="tabpanel-hygiene"
        className="workspace-tabs__tab"
        onClick={() => setTab("hygiene")}
      >
        {t("hygiene.title")}
        {DEMO_HYGIENE_REPORT.summary.total > 0 && (
          <span className="workspace-tabs__badge" style={{ background: hygieneBadgeColor(DEMO_HYGIENE_REPORT.summary) }}>
            {DEMO_HYGIENE_REPORT.summary.total}
          </span>
        )}
      </button>
    </WorkspaceTabs>
  );

  return (
    <div className="app-shell">
      <Header anonymous onOpenSettings={() => setSettingsOpen(true)} onExitDemo={onExit} />

      {/* Demo-mode banner (localized). */}
      <div className="demo-banner">
        <span className="demo-banner__label">{t("demo.bannerTitle")}</span>
        <span className="demo-banner__text">{t("demo.bannerText")}</span>
      </div>

      {workspaceTabs}

      {/* Both tabpanels stay MOUNTED and toggle via display — unmounting the
          check panel would reset useStageReveal and replay the animation on
          every return to the tab. display:none also hides it from a11y. */}
      <main
        role="tabpanel"
        id="tabpanel-hygiene"
        aria-labelledby="tab-hygiene"
        className="hygiene-workspace"
        style={tab === "hygiene" ? undefined : { display: "none" }}
      >
        {/* Left panel mirrors the check tab: summary + section navigation. */}
        <aside className="hygiene-workspace__controls">
          <div className="check-panel">
            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("hygiene.title")}</div>
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 14 }}>
              {t("hygiene.updated", { time: formatDemoTime(DEMO_HYGIENE_REPORT.rules_updated_at, locale) })}
            </div>

            {/* The subtitle sits right before the severity counters. */}
            <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 10 }}>{t("hygiene.subtitle")}</div>
            <HygieneCounters summary={DEMO_HYGIENE_REPORT.summary} />

            <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />

            <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)", marginBottom: 8 }}>{t("hygiene.sections")}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <button className="hygiene-nav__item" aria-pressed={hygieneSection === "all"} onClick={() => setHygieneSection("all")}>
                {t("hygiene.sectionAll")}
                <span className="hygiene-nav__count">{DEMO_HYGIENE_REPORT.summary.total}</span>
              </button>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", margin: "6px 0 2px" }}>{t("hygiene.sectionFirewall")}</div>
              <button
                className="hygiene-nav__item hygiene-nav__item--child"
                aria-pressed={hygieneSection === "fw_forward"}
                onClick={() => setHygieneSection("fw_forward")}
              >
                {t("hygiene.tableForward")}
                <span className="hygiene-nav__count">{hygieneTableCount("fw_forward")}</span>
              </button>
              <button
                className="hygiene-nav__item hygiene-nav__item--child"
                aria-pressed={hygieneSection === "fw_input"}
                onClick={() => setHygieneSection("fw_input")}
              >
                {t("hygiene.tableInput")}
                <span className="hygiene-nav__count">{hygieneTableCount("fw_input")}</span>
              </button>
              <button
                className="hygiene-nav__item"
                style={{ marginTop: 6 }}
                aria-pressed={hygieneSection === "hw_filter"}
                onClick={() => setHygieneSection("hw_filter")}
              >
                {t("stage.hw_filter")}
                <span className="hygiene-nav__count">{hygieneTableCount("hw_filter")}</span>
              </button>
            </div>
          </div>
        </aside>
        <section className="hygiene-workspace__result">
          <RuleHygieneReportView report={DEMO_HYGIENE_REPORT} showCounters={false} filterTable={hygieneSection === "all" ? null : hygieneSection} />
        </section>
      </main>

      <div role="tabpanel" id="tabpanel-check" aria-labelledby="tab-check" style={{ display: tab === "check" ? "contents" : "none" }}>
        <CheckWorkspace
          resultRef={resultRef}
          controls={
            <div className="check-panel">
              <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>{t("check.panelTitle")}</div>

              {/* Address and port share one row, mirroring the live check panel.
                Both are read-only; the target is chosen from the chips below. */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end", marginBottom: 12 }}>
                <div style={{ flex: "1 1 200px", minWidth: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("check.addressLabel")}</div>
                  <input
                    value={selectedTarget.host}
                    disabled
                    readOnly
                    className="form-control mono"
                    style={{
                      border: "1px solid var(--line)",
                      background: "var(--skip-soft)",
                      color: "var(--muted)",
                      borderRadius: "var(--radius-sm)",
                      padding: "11px 12px",
                      fontSize: 14.5,
                      minHeight: 52,
                      cursor: "not-allowed",
                    }}
                  />
                </div>

                {/* The service is derived from the selected target's port; the name
                  is shown on hover, matching the live panel's port field. */}
                <div style={{ flex: "0 0 auto", display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("check.portLabel")}</div>
                  {(() => {
                    const matched = SERVICE_PRESETS.find((p) => p.port === selectedTarget.dst_port);
                    return (
                      <input
                        value={selectedTarget.dst_port}
                        disabled
                        readOnly
                        data-service-preset={matched?.name ?? ""}
                        title={matched ? matched.name : t("check.servicePortHint", { port: selectedTarget.dst_port })}
                        className="form-control mono"
                        style={{
                          border: "1px solid var(--line)",
                          background: "var(--skip-soft)",
                          color: "var(--muted)",
                          borderRadius: "var(--radius-sm)",
                          padding: "11px 12px",
                          fontSize: 13.5,
                          minHeight: 52,
                          width: 132,
                          cursor: "not-allowed",
                        }}
                      />
                    );
                  })()}
                </div>
              </div>

              {/* Iteration 5: the "recent addresses" block reused to hold the two
                demo targets; clicking one selects it. */}
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", marginBottom: 6 }}>{t("demo.targetsLabel")}</div>
              <div className="example-chip-list">
                {DEMO_TARGETS.map((d) => {
                  const active = d.address === targetAddress;
                  return (
                    <button
                      key={d.address}
                      type="button"
                      className="example-chip mono"
                      onClick={() => setTargetAddress(d.address)}
                      style={{
                        borderRadius: 999,
                        padding: "4px 10px",
                        fontSize: 12,
                        borderColor: active ? "var(--accent)" : undefined,
                        color: active ? "var(--accent)" : undefined,
                        background: active ? "var(--accent-soft)" : undefined,
                      }}
                    >
                      {d.address}
                    </button>
                  );
                })}
              </div>

              <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)", marginBottom: 6 }}>{t("check.scenarioLabel")}</div>
              <div
                className="segmented-control"
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--radius-sm)",
                  overflow: "hidden",
                  marginBottom: 14,
                }}
              >
                <button type="button" className="seg-btn" onClick={() => setMode("all")} style={segStyle(mode === "all")}>
                  {t("check.modeAll")}
                </button>
                <button type="button" className="seg-btn" onClick={() => setMode("user")} style={segStyle(mode === "user")}>
                  {t("check.modeUser")}
                </button>
              </div>

              {mode === "user" && (
                <UserPicker
                  users={DEMO_USERS}
                  loading={false}
                  errorText={null}
                  query={userQuery}
                  onQueryChange={setUserQuery}
                  domainFilter={domainFilter}
                  onDomainFilterChange={setDomainFilter}
                  selectedUserId={selectedUserId}
                  onSelect={setSelectedUserId}
                />
              )}

              <button
                type="button"
                onClick={handleCheck}
                disabled={!canCheck}
                className={`check-submit${canCheck ? " btn-primary" : ""}`}
                style={{
                  width: "100%",
                  border: "none",
                  borderRadius: "var(--radius-sm)",
                  padding: 13,
                  fontSize: 14.5,
                  fontWeight: 700,
                  background: canCheck ? undefined : "var(--skip-soft)",
                  color: canCheck ? undefined : "var(--skip)",
                  cursor: canCheck ? "pointer" : "not-allowed",
                }}
              >
                {mode === "user" && selectedUser ? t("check.submitAs", { name: selectedUser.name }) : t("check.submit")}
              </button>

              <div
                style={{
                  marginTop: 16,
                  background: "var(--panel2)",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--radius-md)",
                  padding: "16px 18px",
                  fontSize: 12.5,
                  color: "var(--muted)",
                  lineHeight: 1.55,
                }}
              >
                <PipelineOrder />
              </div>
            </div>
          }
          result={result ? <TraceResult key={runKey} result={result} /> : <EmptyTraceResult />}
        />
      </div>

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

function hygieneTableCount(table: HygieneTable): number {
  return DEMO_HYGIENE_REPORT.findings.filter((f) => f.table === table).length;
}

function formatDemoTime(iso: string, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

function segStyle(active: boolean): React.CSSProperties {
  return {
    padding: "9px 6px",
    fontSize: 12.5,
    fontWeight: 600,
    background: active ? "var(--accent)" : "var(--panel)",
    color: active ? "var(--accent-contrast)" : "var(--muted)",
  };
}

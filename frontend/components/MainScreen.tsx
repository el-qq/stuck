"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { useI18n } from "@/i18n";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { RuleHygieneReport, RulesRefreshResponse, TraceResponse } from "@/lib/types";
import { downloadBlob, defaultRulesExportFilename } from "@/lib/download";
import { Header } from "./Header";
import { WorkspaceTabs } from "./WorkspaceTabs";
import { SettingsModal } from "./SettingsModal";
import { RulesRefreshModal } from "./RulesRefreshModal";
import { HygieneCounters, HygieneTable, RuleHygieneReportView, hygieneBadgeColor } from "./RuleHygieneReportView";
import { AccessDiagnosticModal } from "./AccessDiagnosticModal";
import { TraceForm, TraceSubmitPayload } from "./TraceForm";
import { TraceResult } from "./TraceResult";
import { CheckWorkspace, EmptyTraceResult } from "./CheckWorkspace";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";

export function MainScreen() {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();
  const { t, locale } = useI18n();

  const [settingsOpen, setSettingsOpen] = useState(false);
  // Older backends omit the profile; retain their existing UI behavior.  New
  // backends always provide it and enforce the same decision server-side.
  const accessProfile = session.session?.access_profile;
  const traceAllowed = accessProfile?.trace_allowed ?? true;
  const [accessModalOpen, setAccessModalOpen] = useState(false);
  const [accessRefreshing, setAccessRefreshing] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  // ---- rules export ----
  const exportEnabled = (session.session?.rules_export_enabled ?? false) && traceAllowed;
  const [exporting, setExporting] = useState(false);

  // ---- rule hygiene (top-level workspace tab) ----
  const hygieneEnabled = (session.session?.rule_hygiene_enabled ?? false) && traceAllowed;
  const [tab, setTab] = useState<"check" | "hygiene">("check");
  const [hygieneSection, setHygieneSection] = useState<"all" | HygieneTable>("all");
  // The report is cached until the rules snapshot is refreshed (it is a pure
  // function of the snapshot); null = not loaded yet / invalidated.
  const [hygieneReport, setHygieneReport] = useState<RuleHygieneReport | null>(null);
  const [hygieneLoading, setHygieneLoading] = useState(false);
  const [hygieneError, setHygieneError] = useState<string | null>(null);

  const loadHygiene = useCallback(
    async (refresh: boolean) => {
      setHygieneLoading(true);
      setHygieneError(null);
      try {
        const res = await api.getRuleHygiene(refresh);
        setHygieneReport(res);
        if (refresh) session.markRulesUpdated(res.rules_updated_at);
      } catch (e) {
        const apiErr = toApiError(e);
        if (session.handleAuthError(apiErr)) return;
        setHygieneError(errorMessage(apiErr));
      } finally {
        setHygieneLoading(false);
      }
    },
    [session, errorMessage],
  );

  // Fetch on ENTERING the tab without a cached report. `loadHygiene` is
  // intentionally not a dependency — its identity may change with context
  // re-renders and re-running on that would loop the request (seen before).
  useEffect(() => {
    if (tab === "hygiene" && hygieneEnabled && hygieneReport === null && !hygieneLoading) void loadHygiene(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, hygieneReport, hygieneEnabled]);

  const runExport = useCallback(async () => {
    setExporting(true);
    try {
      const { blob, filename } = await api.exportRules();
      const server = session.session?.server ?? "ngfw";
      // The export can be large — hand it straight to the browser download
      // instead of parsing it into state.
      downloadBlob(blob, filename ?? defaultRulesExportFilename(server));
    } catch (e) {
      const apiErr = toApiError(e);
      if (!session.handleAuthError(apiErr)) {
        toast.show(errorMessage(apiErr), "error");
      }
    } finally {
      setExporting(false);
    }
  }, [session, toast, errorMessage]);

  // ---- rules refresh state ----
  const rulesLoaded = session.session?.rules_loaded ?? false;
  // v2 (FR-2.5): last rules snapshot load moment for the current pair. On a
  // re-login of a cached pair this comes pre-filled from GET /api/session.
  const rulesUpdatedAt = session.session?.rules_updated_at ?? null;
  const [refreshOpen, setRefreshOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshResult, setRefreshResult] = useState<RulesRefreshResponse | null>(null);
  const [refreshError, setRefreshError] = useState<ApiError | null>(null);
  // Iteration 3 (#9): bumped after each successful refresh so TraceForm
  // invalidates its local users cache and re-fetches GET /api/users.
  const [usersVersion, setUsersVersion] = useState(0);
  const autoRefreshTriggered = useRef(false);

  useEffect(() => {
    if (!traceAllowed) setAccessModalOpen(true);
  }, [traceAllowed]);

  const runAccessRefresh = useCallback(async () => {
    setAccessRefreshing(true);
    setAccessError(null);
    try {
      const profile = await session.refreshAccessProfile();
      if (profile.trace_allowed) setAccessModalOpen(false);
    } catch (e) {
      const apiErr = toApiError(e);
      if (session.handleAuthError(apiErr)) return;
      setAccessError(errorMessage(apiErr));
    } finally {
      setAccessRefreshing(false);
    }
  }, [session, errorMessage]);

  const runRefresh = useCallback(async () => {
    if (!traceAllowed) return;
    setRefreshOpen(true);
    setRefreshing(true);
    setRefreshResult(null);
    setRefreshError(null);
    try {
      const res = await api.refreshRules();
      setRefreshResult(res);
      session.markRulesUpdated(res.rules_updated_at);
      setUsersVersion((v) => v + 1);
      // The hygiene report is a function of the snapshot — invalidate the
      // cache; the effect above re-fetches when (or while) the tab is open.
      setHygieneReport(null);
    } catch (e) {
      const apiErr = toApiError(e);
      if (session.handleAuthError(apiErr)) return;
      setRefreshError(apiErr);
    } finally {
      setRefreshing(false);
    }
  }, [session, traceAllowed]);

  // FR-2.1: on first login for this admin+server pair, load the rule snapshot
  // automatically (visualized with the step popup, as in the design mock).
  useEffect(() => {
    if (traceAllowed && !rulesLoaded && !autoRefreshTriggered.current) {
      autoRefreshTriggered.current = true;
      void runRefresh();
    }
  }, [traceAllowed, rulesLoaded, runRefresh]);

  // ---- trace state ----
  const [tracing, setTracing] = useState(false);
  const [traceResult, setTraceResult] = useState<TraceResponse | null>(null);
  const resultRef = useRef<HTMLElement>(null);
  useMobileResultScroll(resultRef, traceResult);

  async function runTrace(payload: TraceSubmitPayload) {
    if (!traceAllowed) return;
    setTracing(true);
    try {
      const res = await api.trace({
        url: payload.url,
        ...(payload.userId ? { user_id: payload.userId } : {}),
        ...(payload.sourceIp ? { source_ip: payload.sourceIp } : {}),
      });
      setTraceResult(res);
      // v2: trace reports which snapshot it ran on (covers lazy first load).
      session.markRulesUpdated(res.rules_updated_at);
    } catch (e) {
      const apiErr = toApiError(e);
      if (!session.handleAuthError(apiErr)) {
        toast.show(errorMessage(apiErr), "error");
      }
    } finally {
      setTracing(false);
    }
  }

  // Top-level sections; the tab bar only exists when hygiene is enabled. The
  // bar sticks under the header (WorkspaceTabs), surviving result scrolling.
  const workspaceTabs = hygieneEnabled ? (
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
        {hygieneReport !== null && hygieneReport.summary.total > 0 && (
          <span className="workspace-tabs__badge" style={{ background: hygieneBadgeColor(hygieneReport.summary) }}>
            {hygieneReport.summary.total}
          </span>
        )}
      </button>
    </WorkspaceTabs>
  ) : null;

  return (
    <div className="app-shell">
      <Header
        rulesLoaded={rulesLoaded}
        rulesUpdatedAt={rulesUpdatedAt}
        refreshing={refreshing}
        onRefresh={() => void runRefresh()}
        accessAllowed={traceAllowed}
        onOpenSettings={() => setSettingsOpen(true)}
        exportEnabled={exportEnabled}
        exporting={exporting}
        onExport={() => void runExport()}
      />

      {workspaceTabs}

      {hygieneEnabled && (
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
              {hygieneReport && (
                <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 14 }}>
                  {t("hygiene.updated", { time: formatTime(hygieneReport.rules_updated_at, locale) })}
                </div>
              )}

              {/* The subtitle sits right before the severity counters. */}
              <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 10 }}>{t("hygiene.subtitle")}</div>
              {hygieneReport && (
                <>
                  <HygieneCounters summary={hygieneReport.summary} />

                  <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />

                  <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)", marginBottom: 8 }}>{t("hygiene.sections")}</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <button className="hygiene-nav__item" aria-pressed={hygieneSection === "all"} onClick={() => setHygieneSection("all")}>
                      {t("hygiene.sectionAll")}
                      <span className="hygiene-nav__count">{hygieneReport.summary.total}</span>
                    </button>
                    <div style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", margin: "6px 0 2px" }}>{t("hygiene.sectionFirewall")}</div>
                    <button
                      className="hygiene-nav__item hygiene-nav__item--child"
                      aria-pressed={hygieneSection === "fw_forward"}
                      onClick={() => setHygieneSection("fw_forward")}
                    >
                      {t("hygiene.tableForward")}
                      <span className="hygiene-nav__count">{hygieneReport.findings.filter((f) => f.table === "fw_forward").length}</span>
                    </button>
                    <button
                      className="hygiene-nav__item hygiene-nav__item--child"
                      aria-pressed={hygieneSection === "fw_input"}
                      onClick={() => setHygieneSection("fw_input")}
                    >
                      {t("hygiene.tableInput")}
                      <span className="hygiene-nav__count">{hygieneReport.findings.filter((f) => f.table === "fw_input").length}</span>
                    </button>
                  </div>

                  <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />
                </>
              )}
              {/* Re-check re-pulls the snapshot (?refresh=true), like export. */}
              <button
                className="btn-primary"
                onClick={() => void loadHygiene(true)}
                disabled={hygieneLoading}
                style={{ width: "100%", border: "none", borderRadius: "var(--radius-sm)", padding: 11, fontSize: 13.5, fontWeight: 700 }}
              >
                {hygieneLoading ? t("hygiene.rechecking") : t("hygiene.recheck")}
              </button>
            </div>
          </aside>
          <section className="hygiene-workspace__result">
            {hygieneLoading && !hygieneReport && <div style={{ padding: "22px 0", fontSize: 13.5, color: "var(--muted)" }}>{t("hygiene.loading")}</div>}
            {hygieneError && !hygieneLoading && (
              <div
                role="alert"
                style={{
                  fontSize: 13,
                  color: "var(--bad)",
                  background: "var(--bad-soft)",
                  borderRadius: "var(--radius-sm)",
                  padding: "12px 14px",
                  lineHeight: 1.5,
                }}
              >
                {hygieneError}
              </div>
            )}
            {hygieneReport && !hygieneError && (
              <RuleHygieneReportView
                report={hygieneReport}
                port={session.session?.ngfw_port}
                showCounters={false}
                filterTable={hygieneSection === "all" ? null : hygieneSection}
              />
            )}
          </section>
        </main>
      )}

      {/* The check tabpanel stays MOUNTED and toggles via display — unmounting
          would reset useStageReveal and replay the trace animation on every
          return to the tab. */}
      <div
        role={hygieneEnabled ? "tabpanel" : undefined}
        id="tabpanel-check"
        aria-labelledby={hygieneEnabled ? "tab-check" : undefined}
        style={{ display: tab === "check" ? "contents" : "none" }}
      >
        <CheckWorkspace
          resultRef={resultRef}
          controls={
            <>
              {!traceAllowed && (
                <div
                  role="alert"
                  data-testid="access-warning"
                  style={{
                    marginBottom: 14,
                    borderRadius: "var(--radius-sm)",
                    padding: "11px 13px",
                    color: "var(--warn)",
                    background: "var(--warn-soft)",
                    fontSize: 13,
                    lineHeight: 1.45,
                  }}
                >
                  {t("access.persistentWarning")}
                </div>
              )}
              <TraceForm
                rulesLoaded={rulesLoaded}
                traceAllowed={traceAllowed}
                submitting={tracing}
                usersVersion={usersVersion}
                onSubmit={(p) => void runTrace(p)}
              />
            </>
          }
          result={traceResult ? <TraceResult result={traceResult} /> : <EmptyTraceResult />}
        />
      </div>

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}

      <RulesRefreshModal
        open={refreshOpen}
        refreshing={refreshing}
        error={refreshError}
        result={refreshResult}
        onClose={() => setRefreshOpen(false)}
        onRetry={() => void runRefresh()}
      />

      {accessProfile && !traceAllowed && (
        <AccessDiagnosticModal
          open={accessModalOpen}
          profile={accessProfile}
          refreshing={accessRefreshing}
          errorText={accessError}
          onRetry={() => void runAccessRefresh()}
          onLogout={() => void session.logout()}
          onClose={() => setAccessModalOpen(false)}
        />
      )}
    </div>
  );
}

function formatTime(iso: string, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

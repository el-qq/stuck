"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { usePublicConfig } from "@/contexts/PublicConfigContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { useI18n } from "@/i18n";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { RuleHygieneReport, RulesRefreshResponse, TraceResponse } from "@/lib/types";
import { downloadBlob, defaultRulesExportFilename } from "@/lib/download";
import { useRuleSnapshots } from "@/hooks/useRuleSnapshots";
import { AccessDiagnosticModal } from "../auth/AccessDiagnosticModal";
import { HygieneTable, hygieneBadgeColor } from "../rules/RuleHygieneReportView";
import { RuleHygieneWorkspace } from "../rules/RuleHygieneWorkspace";
import { RulesExportConfirmModal } from "../rules/RulesExportConfirmModal";
import { RulesRefreshModal } from "../rules/RulesRefreshModal";
import { diffBadgeColor } from "../rules/SnapshotDiffView";
import { SnapshotComparisonWorkspace } from "../rules/SnapshotComparisonWorkspace";
import { Header } from "../shell/Header";
import { SettingsModal } from "../shell/SettingsModal";
import { WorkspaceTabs } from "../shell/WorkspaceTabs";
import { CheckWorkspace, EmptyTraceResult } from "../trace/CheckWorkspace";
import { TraceForm, TraceSubmitPayload } from "../trace/TraceForm";
import { TraceResult } from "../trace/TraceResult";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";

export function MainScreen() {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();
  const { t } = useI18n();
  const { traceAnimationEnabled } = usePublicConfig();

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
  const [exportConfirmOpen, setExportConfirmOpen] = useState(false);

  // ---- rule hygiene (top-level workspace tab) ----
  const hygieneEnabled = (session.session?.rule_hygiene_enabled ?? false) && traceAllowed;
  const [tab, setTab] = useState<"check" | "hygiene" | "snapshots">("check");
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

  // ---- rule snapshots + diff (top-level workspace tab, docs/source/snapshots.md fork f) ----
  const snapshotsEnabled = (session.session?.rule_snapshots_enabled ?? false) && traceAllowed;
  const snapshotState = useRuleSnapshots({ active: tab === "snapshots", enabled: snapshotsEnabled });
  const { diffChangeCount, invalidateCurrentDiff } = snapshotState;

  const runExport = useCallback(async () => {
    setExporting(true);
    try {
      const { blob, filename } = await api.exportRules();
      const server = session.session?.server ?? "ngfw";
      // The export can be large — hand it straight to the browser download
      // instead of parsing it into state.
      downloadBlob(blob, filename ?? defaultRulesExportFilename(server));
      setExportConfirmOpen(false);
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
      // A refresh invalidates only the live `current` side. The hook also
      // cancels any old in-flight response before another comparison starts.
      invalidateCurrentDiff();
    } catch (e) {
      const apiErr = toApiError(e);
      if (session.handleAuthError(apiErr)) return;
      setRefreshError(apiErr);
    } finally {
      setRefreshing(false);
    }
  }, [invalidateCurrentDiff, session, traceAllowed]);

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

  // Top-level sections; the tab bar only exists when at least one optional
  // panel is enabled. The bar sticks under the header (WorkspaceTabs),
  // surviving result scrolling.
  const showTabs = hygieneEnabled || snapshotsEnabled;
  const workspaceTabs = showTabs ? (
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
      {hygieneEnabled && (
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
      )}
      {snapshotsEnabled && (
        <button
          role="tab"
          id="tab-snapshots"
          aria-selected={tab === "snapshots"}
          aria-controls="tabpanel-snapshots"
          className="workspace-tabs__tab"
          onClick={() => setTab("snapshots")}
        >
          {t("snapshots.title")}
          {diffChangeCount > 0 && (
            <span className="workspace-tabs__badge" style={{ background: diffBadgeColor(snapshotState.diff!.summary) }}>
              {diffChangeCount}
            </span>
          )}
        </button>
      )}
    </WorkspaceTabs>
  ) : null;

  return (
    <div className="app-shell">
      <Header
        identity={session.session ? { login: session.session.login, server: session.session.server } : null}
        onLogout={() => void session.logout()}
        rulesLoaded={rulesLoaded}
        rulesUpdatedAt={rulesUpdatedAt}
        refreshing={refreshing}
        onRefresh={() => void runRefresh()}
        accessAllowed={traceAllowed}
        onOpenSettings={() => setSettingsOpen(true)}
        exportEnabled={exportEnabled}
        exporting={exporting}
        onExport={() => setExportConfirmOpen(true)}
      />

      {workspaceTabs}

      {/* Hygiene and snapshots are conditionally rendered (not display:none) —
          unlike the check tab, neither has animation state to preserve across
          a remount, and keeping both mounted at once duplicates group labels
          they share (e.g. "Firewall · Forward"), breaking strict-mode text
          queries. Only the active one of the two is ever in the DOM. */}
      {hygieneEnabled && tab === "hygiene" && (
        <RuleHygieneWorkspace
          report={hygieneReport}
          loading={hygieneLoading}
          error={hygieneError}
          section={hygieneSection}
          onSectionChange={setHygieneSection}
          onRecheck={() => void loadHygiene(true)}
          port={session.session?.ngfw_port}
        />
      )}

      {snapshotsEnabled && tab === "snapshots" && (
        <SnapshotComparisonWorkspace state={snapshotState} rulesUpdatedAt={rulesUpdatedAt} port={session.session?.ngfw_port} />
      )}

      {/* The check tabpanel stays MOUNTED and toggles via display — unmounting
          would reset useStageReveal and replay the trace animation on every
          return to the tab. */}
      <div
        role={showTabs ? "tabpanel" : undefined}
        id="tabpanel-check"
        aria-labelledby={showTabs ? "tab-check" : undefined}
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
          result={
            traceResult ? (
              <TraceResult
                result={traceResult}
                traceAnimationEnabled={traceAnimationEnabled}
                ngfwServer={session.session?.server}
                ngfwPort={session.session?.ngfw_port}
              />
            ) : (
              <EmptyTraceResult />
            )
          }
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

      <RulesExportConfirmModal
        open={exportConfirmOpen}
        downloading={exporting}
        onCancel={() => setExportConfirmOpen(false)}
        onDownload={() => void runExport()}
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

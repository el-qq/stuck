"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { usePublicConfig } from "@/contexts/PublicConfigContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { RuleHygieneReport, RulesRefreshResponse } from "@/lib/types";
import { downloadBlob, defaultRulesExportFilename } from "@/lib/download";
import { getActiveWorkspaceTab, setActiveWorkspaceTab, WorkspaceTab } from "@/lib/storage";
import { useRuleSnapshots } from "@/hooks/useRuleSnapshots";
import { useAccessCompare } from "@/hooks/useAccessCompare";
import { useCheck } from "@/hooks/useCheck";
import { AccessDiagnosticModal } from "../auth/AccessDiagnosticModal";
import { HygieneTable } from "../rules/RuleHygieneReportView";
import { RulesExportConfirmModal } from "../rules/RulesExportConfirmModal";
import { RulesRefreshModal } from "../rules/RulesRefreshModal";
import { Header } from "../shell/Header";
import { SettingsModal } from "../shell/SettingsModal";
import { Workspace } from "./Workspace";

export function MainScreen() {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();
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
  // Restore the section chosen before a reload (F5) from sessionStorage; a
  // missing/unavailable value falls back to "check" via `Workspace`'s own
  // availability clamp.
  const [tab, setTab] = useState<WorkspaceTab>(() => getActiveWorkspaceTab() ?? "check");
  useEffect(() => {
    setActiveWorkspaceTab(tab);
  }, [tab]);
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
  const { invalidateCurrentDiff } = snapshotState;

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
  // Iteration 3 (#9): bumped after each successful refresh so the check tab
  // invalidates its local users cache and re-fetches GET /api/users.
  const [usersVersion, setUsersVersion] = useState(0);
  const autoRefreshTriggered = useRef(false);

  // ---- access compare (top-level workspace tab, docs/source/comparison.md) ----
  const compareEnabled = (session.session?.access_compare_enabled ?? false) && traceAllowed;
  const compareState = useAccessCompare({ rulesLoaded, traceAllowed, usersVersion });
  const { invalidateResult: invalidateCompareResult } = compareState;

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
      // The shown access-compare result (if any) was computed on the
      // pre-refresh snapshot — clear it rather than silently keep a stale
      // diff on screen (docs/source/comparison.md §3.i case 6).
      invalidateCompareResult();
    } catch (e) {
      const apiErr = toApiError(e);
      if (session.handleAuthError(apiErr)) return;
      setRefreshError(apiErr);
    } finally {
      setRefreshing(false);
    }
  }, [invalidateCompareResult, invalidateCurrentDiff, session, traceAllowed]);

  // FR-2.1: on first login for this admin+server pair, load the rule snapshot
  // automatically (visualized with the step popup, as in the design mock).
  useEffect(() => {
    if (traceAllowed && !rulesLoaded && !autoRefreshTriggered.current) {
      autoRefreshTriggered.current = true;
      void runRefresh();
    }
  }, [traceAllowed, rulesLoaded, runRefresh]);

  // ---- check tab (top-level workspace tab) ----
  const checkState = useCheck({ rulesLoaded, traceAllowed, usersVersion });

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

      <Workspace
        tab={tab}
        onTabChange={setTab}
        check={checkState}
        hygiene={{
          enabled: hygieneEnabled,
          report: hygieneReport,
          loading: hygieneLoading,
          error: hygieneError,
          section: hygieneSection,
          onSectionChange: setHygieneSection,
          onRecheck: () => void loadHygiene(true),
        }}
        snapshots={{ enabled: snapshotsEnabled, state: snapshotState, rulesUpdatedAt }}
        compare={{ enabled: compareEnabled, state: compareState }}
        server={session.session?.server}
        port={session.session?.ngfw_port}
        traceAnimationEnabled={traceAnimationEnabled}
      />

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

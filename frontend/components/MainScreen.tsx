"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { RulesRefreshResponse, TraceResponse } from "@/lib/types";
import { downloadBlob, defaultRulesExportFilename } from "@/lib/download";
import { Header } from "./Header";
import { SettingsModal } from "./SettingsModal";
import { RulesRefreshModal } from "./RulesRefreshModal";
import { TraceForm, TraceSubmitPayload } from "./TraceForm";
import { TraceResult } from "./TraceResult";
import { CheckWorkspace, EmptyTraceResult } from "./CheckWorkspace";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";

export function MainScreen() {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();

  const [settingsOpen, setSettingsOpen] = useState(false);

  // ---- rules export (v2.3 §3.8) ----
  const exportEnabled = session.session?.rules_export_enabled ?? false;
  const [exporting, setExporting] = useState(false);

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

  const runRefresh = useCallback(async () => {
    setRefreshOpen(true);
    setRefreshing(true);
    setRefreshResult(null);
    setRefreshError(null);
    try {
      const res = await api.refreshRules();
      setRefreshResult(res);
      session.markRulesUpdated(res.rules_updated_at);
      setUsersVersion((v) => v + 1);
    } catch (e) {
      const apiErr = toApiError(e);
      if (session.handleAuthError(apiErr)) return;
      setRefreshError(apiErr);
    } finally {
      setRefreshing(false);
    }
  }, [session]);

  // FR-2.1: on first login for this admin+server pair, load the rule snapshot
  // automatically (visualized with the step popup, as in the design mock).
  useEffect(() => {
    if (!rulesLoaded && !autoRefreshTriggered.current) {
      autoRefreshTriggered.current = true;
      void runRefresh();
    }
  }, [rulesLoaded, runRefresh]);

  // ---- trace state ----
  const [tracing, setTracing] = useState(false);
  const [traceResult, setTraceResult] = useState<TraceResponse | null>(null);
  const resultRef = useRef<HTMLElement>(null);
  useMobileResultScroll(resultRef, traceResult);

  async function runTrace(payload: TraceSubmitPayload) {
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

  return (
    <div className="app-shell">
      <Header
        rulesLoaded={rulesLoaded}
        rulesUpdatedAt={rulesUpdatedAt}
        refreshing={refreshing}
        onRefresh={() => void runRefresh()}
        onOpenSettings={() => setSettingsOpen(true)}
        exportEnabled={exportEnabled}
        exporting={exporting}
        onExport={() => void runExport()}
      />

      <CheckWorkspace
        resultRef={resultRef}
        controls={<TraceForm rulesLoaded={rulesLoaded} submitting={tracing} usersVersion={usersVersion} onSubmit={(p) => void runTrace(p)} />}
        result={traceResult ? <TraceResult result={traceResult} /> : <EmptyTraceResult />}
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
    </div>
  );
}

"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { useI18n } from "@/i18n";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { RulesRefreshResponse, TraceResponse } from "@/lib/types";
import { downloadBlob, defaultRulesExportFilename } from "@/lib/download";
import { Header } from "./Header";
import { SettingsModal } from "./SettingsModal";
import { RulesRefreshModal } from "./RulesRefreshModal";
import { AccessDiagnosticModal } from "./AccessDiagnosticModal";
import { TraceForm, TraceSubmitPayload } from "./TraceForm";
import { TraceResult } from "./TraceResult";
import { CheckWorkspace, EmptyTraceResult } from "./CheckWorkspace";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";

export function MainScreen() {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();
  const { t } = useI18n();

  const [settingsOpen, setSettingsOpen] = useState(false);
  // Older backends omit the profile; retain their existing UI behavior.  New
  // backends always provide it and enforce the same decision server-side.
  const accessProfile = session.session?.access_profile;
  const traceAllowed = accessProfile?.trace_allowed ?? true;
  const [accessModalOpen, setAccessModalOpen] = useState(false);
  const [accessRefreshing, setAccessRefreshing] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  // ---- rules export (v2.3 §3.8) ----
  const exportEnabled = (session.session?.rules_export_enabled ?? false) && traceAllowed;
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

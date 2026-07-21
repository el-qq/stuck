"use client";

import React, { useRef, useState } from "react";
import { useI18n } from "@/i18n";
import { DomainType, TraceResponse } from "@/lib/types";
import { DEMO_TARGETS, DEFAULT_DEMO_TARGET, DEMO_USERS, runDemoTrace } from "@/lib/demoData";
import { SERVICE_PRESETS } from "@/lib/servicePresets";
import { Header } from "./Header";
import { SettingsModal } from "./SettingsModal";
import { UserPicker } from "./UserPicker";
import { TraceResult } from "./TraceResult";
import { CheckWorkspace, EmptyTraceResult } from "./CheckWorkspace";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";

/**
 * Iteration 4/5: fully offline demo. Same check screen as the real app, but the
 * address field is read-only and the target is picked from two demo targets
 * shown in the "recent addresses" block. The trace is computed locally by the
 * demo engine (lib/demoData.ts) — no backend, no /api/* calls.
 */
export function DemoScreen({ onExit }: { onExit: () => void }) {
  const { t } = useI18n();

  const [settingsOpen, setSettingsOpen] = useState(false);
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

  return (
    <div className="app-shell">
      <Header anonymous onOpenSettings={() => setSettingsOpen(true)} onExitDemo={onExit} />

      {/* Demo-mode banner (localized). */}
      <div className="demo-banner">
        <span className="demo-banner__label">{t("demo.bannerTitle")}</span>
        <span className="demo-banner__text">{t("demo.bannerText")}</span>
      </div>

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
              <div style={{ fontWeight: 700, color: "var(--text)", marginBottom: 6, fontSize: 13 }}>{t("check.orderTitle")}</div>
              {t("check.orderText")}
            </div>
          </div>
        }
        result={result ? <TraceResult key={runKey} result={result} /> : <EmptyTraceResult />}
      />

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
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

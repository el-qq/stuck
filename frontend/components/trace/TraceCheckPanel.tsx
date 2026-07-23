"use client";

import React, { useState } from "react";
import { useI18n } from "@/i18n";
import type { TraceTargetController } from "@/hooks/useTraceTarget";
import type { TraceMode, TraceSubjectsState } from "@/hooks/useTraceSubjects";
import { DomainType } from "@/lib/types";
import { PipelineOrder } from "./PipelineOrder";
import { SourceAddressPicker } from "./SourceAddressPicker";
import { TraceTargetFields } from "./TraceTargetFields";
import { UserPicker } from "./UserPicker";
import type { TraceSubmitPayload } from "./TraceForm";

interface Props {
  rulesLoaded: boolean;
  traceAllowed: boolean;
  submitting: boolean;
  mode: TraceMode;
  onModeChange: (mode: TraceMode) => void;
  target: TraceTargetController;
  subjects: TraceSubjectsState;
  onSubmit: (payload: TraceSubmitPayload) => void;
}

/**
 * Shared trace controls. The component owns only local filter inputs; its
 * target and subjects are provided by an adapter. This keeps the demo's
 * offline data path visually and structurally identical to the live form.
 */
export function TraceCheckPanel({ rulesLoaded, traceAllowed, submitting, mode, onModeChange, target, subjects, onSubmit }: Props) {
  const { t } = useI18n();
  const [userQuery, setUserQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState<"all" | DomainType>("all");

  const sourceAddressReady = !subjects.sourceAddressesError && (subjects.sourceAddresses.length === 0 || !!subjects.selectedSourceIp);
  const canCheck =
    traceAllowed &&
    rulesLoaded &&
    target.address.trim().length > 0 &&
    (mode === "all" || (!!subjects.selectedUser && sourceAddressReady)) &&
    !subjects.sourceAddressesLoading &&
    !submitting;

  function handleSubmit() {
    if (!canCheck) return;
    const url = target.submitTarget();
    onSubmit({
      url,
      userId: mode === "user" ? (subjects.selectedUser?.id ?? undefined) : undefined,
      sourceIp: mode === "user" ? (subjects.selectedSourceIp ?? undefined) : undefined,
    });
  }

  return (
    <div
      className="check-panel"
      style={{
        background: "var(--panel)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow)",
        padding: 22,
      }}
    >
      <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>{t("check.panelTitle")}</div>

      <TraceTargetFields target={target} onSubmit={handleSubmit} />

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
        <button type="button" className="seg-btn" onClick={() => onModeChange("all")} style={segStyle(mode === "all")}>
          {t("check.modeAll")}
        </button>
        <button type="button" className="seg-btn" onClick={() => onModeChange("user")} style={segStyle(mode === "user")}>
          {t("check.modeUser")}
        </button>
      </div>

      {mode === "user" && (
        <>
          <UserPicker
            users={subjects.users}
            loading={subjects.usersLoading}
            errorText={subjects.usersError}
            query={userQuery}
            onQueryChange={setUserQuery}
            domainFilter={domainFilter}
            onDomainFilterChange={setDomainFilter}
            selectedUserId={subjects.selectedUserId}
            onSelect={subjects.setSelectedUserId}
          />
          {subjects.selectedUser && (
            <SourceAddressPicker
              addresses={subjects.sourceAddresses}
              loading={subjects.sourceAddressesLoading}
              errorText={subjects.sourceAddressesError}
              selectedIp={subjects.selectedSourceIp}
              onSelect={subjects.setSelectedSourceIp}
            />
          )}
        </>
      )}

      <button
        type="button"
        onClick={handleSubmit}
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
        {submitting
          ? t("check.submitting")
          : mode === "user" && subjects.selectedUser
            ? t("check.submitAs", { name: subjects.selectedUser.name })
            : t("check.submit")}
      </button>

      {!traceAllowed && (
        <div role="alert" className="trace-check-panel__notice">
          {t("access.traceDisabled")}
        </div>
      )}

      {!traceAllowed ? null : !rulesLoaded && <div className="trace-check-panel__notice">{t("check.noRulesWarning")}</div>}

      <div className="trace-check-panel__pipeline">
        <PipelineOrder />
      </div>
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

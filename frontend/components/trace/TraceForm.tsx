"use client";

import React, { useState } from "react";
import { useI18n } from "@/i18n";
import { useTraceSubjects } from "@/hooks/useTraceSubjects";
import { useTraceTarget } from "@/hooks/useTraceTarget";
import { DomainType } from "@/lib/types";
import { PipelineOrder } from "./PipelineOrder";
import { SourceAddressPicker } from "./SourceAddressPicker";
import { TraceTargetFields } from "./TraceTargetFields";
import { UserPicker } from "./UserPicker";

export interface TraceSubmitPayload {
  url: string;
  userId?: string;
  sourceIp?: string;
}

interface Props {
  rulesLoaded: boolean;
  /** False when the backend has identified a known insufficient NGFW role. */
  traceAllowed: boolean;
  submitting: boolean;
  /** Bumped after a successful rules refresh, invalidating local subject data. */
  usersVersion: number;
  onSubmit: (payload: TraceSubmitPayload) => void;
}

/** Compose trace-target controls with the optional user/source-IP scenario. */
export function TraceForm({ rulesLoaded, traceAllowed, submitting, usersVersion, onSubmit }: Props) {
  const { t } = useI18n();
  const [mode, setMode] = useState<"all" | "user">("all");
  const [userQuery, setUserQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState<"all" | DomainType>("all");
  const target = useTraceTarget();
  const subjects = useTraceSubjects({ mode, rulesLoaded, usersVersion });

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
        <button type="button" className="seg-btn" onClick={() => setMode("all")} style={segStyle(mode === "all")}>
          {t("check.modeAll")}
        </button>
        <button type="button" className="seg-btn" onClick={() => setMode("user")} style={segStyle(mode === "user")}>
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
        <div
          role="alert"
          style={{
            marginTop: 10,
            fontSize: 12.5,
            color: "var(--warn)",
            background: "var(--warn-soft)",
            borderRadius: "var(--radius-sm)",
            padding: "10px 12px",
            lineHeight: 1.45,
          }}
        >
          {t("access.traceDisabled")}
        </div>
      )}

      {!traceAllowed
        ? null
        : !rulesLoaded && (
            <div
              style={{
                marginTop: 10,
                fontSize: 12.5,
                color: "var(--warn)",
                background: "var(--warn-soft)",
                borderRadius: "var(--radius-sm)",
                padding: "10px 12px",
                lineHeight: 1.45,
              }}
            >
              {t("check.noRulesWarning")}
            </div>
          )}

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

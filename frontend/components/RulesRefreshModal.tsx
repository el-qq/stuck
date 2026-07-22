"use client";

import React, { useEffect, useRef, useState } from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { ApiError } from "@/lib/errors";
import { RulesRefreshResponse } from "@/lib/types";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { useDialog } from "@/hooks/useDialog";
import { useMediaQuery } from "@/hooks/useMediaQuery";

interface Step {
  labelKey: MessageKey;
  count: (r: RulesRefreshResponse) => number;
}

// Purely a visual progression while the single POST /api/rules/refresh call is
// in flight (the contract has no incremental progress endpoint) — once the
// real response lands we snap to 100% and show the real counts.
const STEPS: Step[] = [
  { labelKey: "rules.stepConnect", count: () => NaN },
  { labelKey: "rules.stepUsers", count: (r) => r.counts.users },
  { labelKey: "rules.stepAliases", count: (r) => r.counts.aliases },
  { labelKey: "rules.stepFirewallPreFilter", count: (r) => r.counts.firewall_pre_filter },
  { labelKey: "rules.stepHardware", count: (r) => r.counts.hardware_rules ?? NaN },
  { labelKey: "rules.stepLanNetworks", count: (r) => r.counts.lan_networks ?? NaN },
  { labelKey: "rules.stepDnsZones", count: (r) => r.counts.dns_zones ?? NaN },
  { labelKey: "rules.stepFirewallDnat", count: (r) => r.counts.firewall_dnat },
  { labelKey: "rules.stepFirewallForward", count: (r) => r.counts.firewall_forward },
  { labelKey: "rules.stepFirewallInput", count: (r) => r.counts.firewall_input },
  { labelKey: "rules.stepFirewallSnat", count: (r) => r.counts.firewall_snat },
  { labelKey: "rules.stepContentFilter", count: (r) => r.counts.content_filter_rules },
  { labelKey: "rules.stepSpeedLimit", count: (r) => r.counts.speed_limit_rules },
  { labelKey: "rules.stepIpsBypass", count: (r) => r.counts.ips_bypass },
];

const STEP_INTERVAL_MS = 380;

interface Props {
  open: boolean;
  refreshing: boolean;
  error: ApiError | null;
  result: RulesRefreshResponse | null;
  onClose: () => void;
  onRetry: () => void;
}

export function RulesRefreshModal({ open, refreshing, error, result, onClose, onRetry }: Props) {
  const { t } = useI18n();
  const errorMessage = useApiErrorMessage();
  const [stepIndex, setStepIndex] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const reduceMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const dialogRef = useDialog(open, refreshing ? undefined : onClose);

  useEffect(() => {
    if (!open) return;
    setStepIndex(0);
    if (timerRef.current) clearInterval(timerRef.current);
    if (reduceMotion) {
      setStepIndex(STEPS.length - 1);
      return;
    }
    timerRef.current = setInterval(() => {
      setStepIndex((i) => (i < STEPS.length - 1 ? i + 1 : i));
    }, STEP_INTERVAL_MS);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [open, reduceMotion]);

  useEffect(() => {
    if (!refreshing && (result || error)) {
      if (timerRef.current) clearInterval(timerRef.current);
      setStepIndex(STEPS.length);
    }
  }, [refreshing, result, error]);

  if (!open) return null;

  const done = !refreshing && !!result;
  const failed = !refreshing && !!error;
  const progress = Math.min(100, Math.round((stepIndex / STEPS.length) * 100));

  return (
    <div className="modal-backdrop">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={failed ? t("rules.failedTitle") : done ? t("rules.modalTitleDone") : t("rules.modalTitleLoading")}
        tabIndex={-1}
        className="modal-card modal-card--rules"
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
          <span
            style={{
              display: "inline-block",
              fontSize: 18,
              fontWeight: 700,
              color: failed ? "var(--bad)" : done ? "var(--ok)" : "var(--accent)",
              animation: done || failed ? "none" : "spin 1s linear infinite",
            }}
          >
            {failed ? "✕" : "⟳"}
          </span>
          <div style={{ fontSize: 16, fontWeight: 700 }}>
            {failed ? t("rules.failedTitle") : done ? t("rules.modalTitleDone") : t("rules.modalTitleLoading")}
          </div>
        </div>

        {!failed && (
          <div
            style={{
              height: 8,
              background: "var(--panel2)",
              borderRadius: 999,
              overflow: "hidden",
              margin: "18px 0",
            }}
          >
            <div
              style={{
                height: "100%",
                width: `${done ? 100 : progress}%`,
                background: done ? "var(--ok)" : "var(--accent)",
                borderRadius: 999,
                transition: "width .35s ease, background .3s ease",
              }}
            />
          </div>
        )}

        {failed && error && (
          <div
            style={{
              fontSize: 13,
              color: "var(--bad)",
              background: "var(--bad-soft)",
              borderRadius: "var(--radius-sm)",
              padding: "12px 14px",
              margin: "14px 0",
              lineHeight: 1.5,
            }}
          >
            {errorMessage(error)}
          </div>
        )}

        {!failed && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 22 }}>
            {STEPS.map((step, i) => {
              const stepDone = i < stepIndex || done;
              const active = i === stepIndex && !done;
              const count = result ? step.count(result) : NaN;
              return (
                <div
                  key={step.labelKey}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    opacity: stepDone || active ? 1 : 0.45,
                    transition: "opacity .3s ease",
                  }}
                >
                  <span
                    style={{
                      width: 20,
                      textAlign: "center",
                      fontWeight: 700,
                      color: stepDone ? "var(--ok)" : active ? "var(--accent)" : "var(--skip)",
                      display: "inline-block",
                      animation: active ? "spin 1s linear infinite" : "none",
                    }}
                  >
                    {stepDone ? "✓" : active ? "⟳" : "·"}
                  </span>
                  <span style={{ flex: 1, fontSize: 13.5 }}>{t(step.labelKey)}</span>
                  {stepDone && !Number.isNaN(count) && (
                    <span className="mono" style={{ fontSize: 12.5, color: "var(--muted)" }}>
                      {count}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {failed ? (
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn-outline" onClick={onClose} style={modalBtnStyle}>
              {t("common.close")}
            </button>
            <button className="btn-primary" onClick={onRetry} style={modalBtnStyle}>
              {t("common.retry")}
            </button>
          </div>
        ) : (
          <button className="btn-primary" onClick={onClose} disabled={!done} style={modalBtnStyle}>
            {done ? t("rules.done") : t("common.loading")}
          </button>
        )}
      </div>
    </div>
  );
}

const modalBtnStyle: React.CSSProperties = {
  flex: 1,
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 700,
};

"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { SERVICE_PRESETS } from "@/lib/servicePresets";
import { TraceTargetController } from "@/hooks/useTraceTarget";

interface Props {
  target: TraceTargetController;
  onSubmit: () => void;
}

/** Presentational controls for a trace target, its optional port and recents. */
export function TraceTargetFields({ target, onSubmit }: Props) {
  const { t } = useI18n();
  const matchedPreset = target.effectivePort === null ? null : (SERVICE_PRESETS.find((preset) => preset.port === target.effectivePort) ?? null);
  const portTitle =
    target.effectivePort === null ? t("check.portDefault") : matchedPreset ? matchedPreset.name : t("check.servicePortHint", { port: target.effectivePort });

  return (
    <>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end", marginBottom: 10 }}>
        <div style={{ flex: "1 1 200px", minWidth: 0, display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("check.addressLabel")}</div>
          <input
            value={target.address}
            title={target.targetPreview || undefined}
            onChange={(event) => target.setAddress(event.target.value)}
            onBlur={target.normalizeAddressOnBlur}
            onPaste={(event) => {
              const text = event.clipboardData.getData("text");
              if (!text.trim()) return;
              event.preventDefault();
              target.applyTarget(text);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter") onSubmit();
            }}
            placeholder={t("check.addressPlaceholder")}
            className="form-control mono"
            style={{
              border: "1px solid var(--line)",
              background: "var(--panel2)",
              color: "var(--text)",
              borderRadius: "var(--radius-sm)",
              padding: "11px 12px",
              fontSize: 14.5,
              minHeight: 52,
              textOverflow: "ellipsis",
            }}
          />
        </div>

        <div style={{ flex: "0 0 auto", display: "flex", flexDirection: "column", gap: 6 }}>
          <label htmlFor="port-input" style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>
            {t("check.portLabel")}
          </label>
          <input
            id="port-input"
            list="port-presets"
            inputMode="numeric"
            value={target.port ?? ""}
            onChange={(event) => target.handlePortInput(event.target.value)}
            title={portTitle}
            placeholder={t("check.portDefault")}
            className="form-control mono"
            style={{
              border: "1px solid var(--line)",
              background: "var(--panel2)",
              color: "var(--text)",
              borderRadius: "var(--radius-sm)",
              padding: "11px 12px",
              fontSize: 13.5,
              minHeight: 52,
              width: 132,
            }}
          />
          <datalist id="port-presets">
            {SERVICE_PRESETS.map((preset) => (
              <option key={preset.name} value={preset.port} label={preset.name} />
            ))}
          </datalist>
        </div>
      </div>

      {target.recentUrls.length > 0 && (
        <div className="example-chip-list" style={{ marginBottom: 14 }}>
          {target.recentUrls.map((url) => (
            <button
              key={url}
              type="button"
              className="example-chip mono"
              title={url}
              onClick={() => target.applyTarget(url)}
              style={{
                borderRadius: 999,
                padding: "4px 10px",
                fontSize: 12,
                maxWidth: "100%",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {url}
            </button>
          ))}
        </div>
      )}
    </>
  );
}

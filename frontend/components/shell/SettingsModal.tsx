"use client";

import React from "react";
import { useSettings, ACCENT_OPTIONS } from "@/contexts/SettingsContext";
import { useI18n, SUPPORTED_LOCALES, Locale } from "@/i18n";
import { useDialog } from "@/hooks/useDialog";

export function SettingsModal({ onClose }: { onClose: () => void }) {
  const { theme, setTheme, accent, setAccent } = useSettings();
  const { locale, setLocale, t } = useI18n();
  const dialogRef = useDialog(true, onClose);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("settings.title")}
        tabIndex={-1}
        className="modal-card modal-card--settings"
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <div style={{ fontSize: 16, fontWeight: 700 }}>{t("settings.title")}</div>
          <button className="icon-btn" onClick={onClose} aria-label={t("common.close")} style={closeBtnStyle}>
            ✕
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div>
            <div style={sectionLabelStyle}>{t("settings.themeLabel")}</div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="seg-btn" onClick={() => setTheme("light")} style={segStyle(theme === "light")}>
                ☀ {t("settings.themeLight")}
              </button>
              <button className="seg-btn" onClick={() => setTheme("dark")} style={segStyle(theme === "dark")}>
                ☾ {t("settings.themeDark")}
              </button>
            </div>
          </div>

          <div>
            <div style={sectionLabelStyle}>{t("settings.accentLabel")}</div>
            <div style={{ display: "flex", gap: 10 }}>
              {ACCENT_OPTIONS.map((opt) => (
                <button
                  key={opt.id}
                  className="accent-swatch"
                  onClick={() => setAccent(opt.value)}
                  aria-label={opt.id}
                  aria-pressed={accent === opt.value}
                  style={{
                    width: 32,
                    height: 32,
                    background: opt.value,
                    border: accent === opt.value ? "3px solid var(--text)" : "3px solid var(--panel)",
                    boxShadow: "0 0 0 1px var(--line)",
                  }}
                />
              ))}
            </div>
          </div>

          <div>
            <div style={sectionLabelStyle}>{t("settings.languageLabel")}</div>
            <select
              className="form-control"
              value={locale}
              onChange={(e) => setLocale(e.target.value as Locale)}
              style={{
                width: "100%",
                border: "1px solid var(--line)",
                background: "var(--panel2)",
                color: "var(--text)",
                borderRadius: "var(--radius-sm)",
                padding: "9px 10px",
                fontSize: 13.5,
              }}
            >
              {SUPPORTED_LOCALES.map((l) => (
                <option key={l.code} value={l.code}>
                  {l.nativeName}
                </option>
              ))}
            </select>
          </div>

          <div style={{ fontSize: 11.5, color: "var(--muted)" }}>{t("settings.storageNote")}</div>
        </div>
      </div>
    </div>
  );
}

const closeBtnStyle: React.CSSProperties = {
  borderRadius: "var(--radius-sm)",
  padding: "6px 10px",
  fontSize: 13,
};

const sectionLabelStyle: React.CSSProperties = {
  fontSize: 12.5,
  fontWeight: 600,
  color: "var(--muted)",
  marginBottom: 8,
};

function segStyle(active: boolean): React.CSSProperties {
  return {
    flex: 1,
    padding: "9px 6px",
    fontSize: 12.5,
    fontWeight: 600,
    borderRadius: "var(--radius-sm)",
    background: active ? "var(--accent)" : "var(--panel2)",
    color: active ? "var(--accent-contrast)" : "var(--muted)",
    border: active ? "none" : "1px solid var(--line)",
  };
}

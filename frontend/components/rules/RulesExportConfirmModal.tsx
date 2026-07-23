"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { useDialog } from "@/hooks/useDialog";

interface Props {
  open: boolean;
  downloading: boolean;
  onCancel: () => void;
  onDownload: () => void;
}

/** Confirms the deliberately broad, anonymized rules attachment. */
export function RulesExportConfirmModal({ open, downloading, onCancel, onDownload }: Props) {
  const { t } = useI18n();
  const dialogRef = useDialog(open, downloading ? undefined : onCancel);
  if (!open) return null;

  return (
    <div className="modal-backdrop" onClick={downloading ? undefined : onCancel}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("rulesExport.title")}
        tabIndex={-1}
        className="modal-card modal-card--rules-export"
        data-testid="rules-export-confirmation"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 style={{ margin: "0 0 10px", fontSize: 16 }}>{t("rulesExport.title")}</h2>
        <p style={{ margin: "0 0 20px", color: "var(--muted)", fontSize: 13.5, lineHeight: 1.5 }}>{t("rulesExport.message")}</p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button type="button" className="btn-outline" onClick={onCancel} disabled={downloading} style={buttonStyle}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn-primary" onClick={onDownload} disabled={downloading} style={buttonStyle}>
            {downloading ? t("header.exporting") : t("rulesExport.download")}
          </button>
        </div>
      </div>
    </div>
  );
}

const buttonStyle: React.CSSProperties = {
  flex: "1 1 130px",
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 700,
};

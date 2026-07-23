"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { useDialog } from "@/hooks/useDialog";
import { SnapshotDescriptor } from "@/lib/types";

interface Props {
  snapshot: SnapshotDescriptor | null;
  deleting: boolean;
  errorText: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}

/** Confirms an irreversible snapshot delete (FR-2 — no undo, no server-side trash). */
export function SnapshotDeleteConfirmModal({ snapshot, deleting, errorText, onCancel, onConfirm }: Props) {
  const { t, locale } = useI18n();
  const open = snapshot !== null;
  const dialogRef = useDialog(open, deleting ? undefined : onCancel);
  if (!snapshot) return null;

  const label = snapshot.comment ? snapshot.comment : formatDate(snapshot.created_at, locale);

  return (
    <div className="modal-backdrop" onClick={deleting ? undefined : onCancel}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("snapshots.deleteConfirmTitle")}
        tabIndex={-1}
        className="modal-card modal-card--rules-export"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 style={{ margin: "0 0 10px", fontSize: 16 }}>{t("snapshots.deleteConfirmTitle")}</h2>
        <p style={{ margin: "0 0 12px", color: "var(--muted)", fontSize: 13.5, lineHeight: 1.5 }}>{t("snapshots.deleteConfirmMessage", { label })}</p>
        {errorText && (
          <div
            role="alert"
            style={{
              fontSize: 13,
              color: "var(--bad)",
              background: "var(--bad-soft)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 12px",
              marginBottom: 14,
            }}
          >
            {errorText}
          </div>
        )}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button type="button" className="btn-outline" onClick={onCancel} disabled={deleting} style={buttonStyle}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn-primary" onClick={onConfirm} disabled={deleting} style={{ ...buttonStyle, background: "var(--bad)" }}>
            {deleting ? t("common.loading") : t("snapshots.delete")}
          </button>
        </div>
      </div>
    </div>
  );
}

function formatDate(iso: string, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

const buttonStyle: React.CSSProperties = {
  flex: "1 1 130px",
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 700,
  color: "var(--accent-contrast)",
};

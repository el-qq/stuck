"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { useDialog } from "@/hooks/useDialog";
import { AdminAccessProfile } from "@/lib/types";

const ROLE_KEYS: Record<string, MessageKey> = {
  predefined_admin_write: "access.role.predefined_admin_write",
  predefined_admin_readonly: "access.role.predefined_admin_readonly",
  predefined_reports_view: "access.role.predefined_reports_view",
  predefined_reports_change: "access.role.predefined_reports_change",
  predefined_security_admin: "access.role.predefined_security_admin",
  predefined_firewall_admin: "access.role.predefined_firewall_admin",
  predefined_access_settings_admin: "access.role.predefined_access_settings_admin",
};

interface Props {
  open: boolean;
  profile: AdminAccessProfile;
  refreshing: boolean;
  errorText: string | null;
  onRetry: () => void;
  onLogout: () => void;
  onClose: () => void;
}

/** Explains a server-enforced role restriction without exposing NGFW internals. */
export function AccessDiagnosticModal({ open, profile, refreshing, errorText, onRetry, onLogout, onClose }: Props) {
  const { t } = useI18n();
  const dialogRef = useDialog(open, refreshing ? undefined : onClose);
  const [detailsOpen, setDetailsOpen] = React.useState(false);
  if (!open) return null;

  const roleKey = ROLE_KEYS[profile.role_id] ?? "access.role.unknown";
  const details = [
    [t("access.roleLabel"), t(roleKey)],
    [t("access.moduleLabel"), t("access.moduleTrace")],
    [t("access.statusLabel"), t("access.statusUnavailable")],
  ] as const;

  return (
    <div className="modal-backdrop">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={t("access.modalTitle")}
        tabIndex={-1}
        className="modal-card modal-card--access-diagnostic"
        data-testid="access-diagnostic-modal"
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
          <span aria-hidden="true" style={{ color: "var(--warn)", fontSize: 20, fontWeight: 700 }}>
            !
          </span>
          <h2 style={{ margin: 0, fontSize: 16 }}>{t("access.modalTitle")}</h2>
        </div>
        <p style={{ margin: "0 0 16px", color: "var(--muted)", fontSize: 13.5, lineHeight: 1.5 }}>{t("access.statusInsufficient")}</p>

        <details open={detailsOpen} onToggle={(event) => setDetailsOpen(event.currentTarget.open)} style={{ marginBottom: 18 }}>
          <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 13, fontWeight: 600 }}>
            {detailsOpen ? t("common.hideDetails") : t("common.showDetails")}
          </summary>
          <dl style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: "8px 14px", margin: "12px 0 0" }}>
            {details.map(([label, value]) => (
              <React.Fragment key={label}>
                <dt style={{ color: "var(--muted)", fontSize: 12.5, fontWeight: 600 }}>{label}</dt>
                <dd style={{ margin: 0, fontSize: 13.5, fontWeight: 600 }}>{value}</dd>
              </React.Fragment>
            ))}
          </dl>
        </details>

        {errorText && (
          <div
            role="alert"
            style={{
              marginBottom: 14,
              borderRadius: "var(--radius-sm)",
              padding: "10px 12px",
              color: "var(--bad)",
              background: "var(--bad-soft)",
              fontSize: 13,
            }}
          >
            {errorText}
          </div>
        )}

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button type="button" className="btn-outline" onClick={onClose} disabled={refreshing} data-testid="access-close" style={buttonStyle}>
            {t("common.close")}
          </button>
          <button type="button" className="btn-outline" onClick={onLogout} disabled={refreshing} data-testid="access-logout" style={buttonStyle}>
            {t("header.logout")}
          </button>
          <button type="button" className="btn-primary" onClick={onRetry} disabled={refreshing} data-testid="access-retry" style={buttonStyle}>
            {refreshing ? t("access.retrying") : t("common.retry")}
          </button>
        </div>
      </div>
    </div>
  );
}

const buttonStyle: React.CSSProperties = {
  flex: "1 1 110px",
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 700,
};

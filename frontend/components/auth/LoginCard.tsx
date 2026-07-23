"use client";

import React from "react";
import { useI18n } from "@/i18n";
import type { LoginFormController } from "@/hooks/useLoginForm";
import { LoginCredentials } from "./LoginCredentials";
import { demoButtonStyle, submitButtonStyle, warnBlockStyle } from "./loginStyles";

interface Props {
  form: LoginFormController;
  onEnterDemo: () => void;
}

/** Presentational login card; all authentication effects stay in useLoginForm. */
export function LoginCard({ form, onEnterDemo }: Props) {
  const { t } = useI18n();

  return (
    <form
      className="login-card"
      onSubmit={form.handleSubmit}
      noValidate
      style={{
        width: 400,
        maxWidth: "100%",
        background: "var(--panel)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow)",
        padding: 36,
        animation: "fadeUp .5s ease both",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div
          style={{
            width: 40,
            height: 40,
            borderRadius: 10,
            background: "var(--accent)",
            color: "var(--accent-contrast)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontWeight: 700,
            fontSize: 15,
            flexShrink: 0,
          }}
        >
          ST
        </div>
        <div>
          <div style={{ fontSize: 17, fontWeight: 700 }}>{t("common.appName")}</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>{t("common.appTagline")}</div>
        </div>
      </div>

      <div style={{ height: 1, background: "var(--line)", margin: "20px 0 24px" }} />

      {form.expiredNotice && (
        <div role="alert" style={warnBlockStyle}>
          {t("login.sessionExpiredNotice")}
        </div>
      )}
      {form.bootstrapErrorText && (
        <div role="alert" style={warnBlockStyle}>
          {form.bootstrapErrorText}
        </div>
      )}
      {form.unrestrictedNgfw && (
        <div role="alert" style={warnBlockStyle}>
          {t("login.unrestrictedNgfwWarning")}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <LoginCredentials
          server={form.server}
          loginName={form.loginName}
          password={form.password}
          showPassword={form.showPassword}
          ngfwPort={form.ngfwPort}
          defaultServerLocked={form.defaultServerLocked}
          fieldErrors={form.fieldErrors}
          roHintDismissed={form.roHintDismissed}
          onServerChange={form.setServer}
          onLoginChange={form.setLoginName}
          onPasswordChange={form.setPassword}
          onTogglePassword={form.togglePassword}
          onDismissRoHint={form.dismissRoHint}
        />

        {form.apiErrorText && (
          <div
            role="alert"
            style={{
              fontSize: 12.5,
              color: "var(--bad)",
              background: "var(--bad-soft)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 12px",
              lineHeight: 1.45,
            }}
          >
            {form.apiErrorText}
          </div>
        )}

        {form.twoFactorResetNotice && (
          <div role="alert" style={warnBlockStyle}>
            {t("login.twoFactorResetNotice")}
          </div>
        )}
        {form.readonlyAdminRequiredNotice && (
          <div role="alert" style={warnBlockStyle}>
            {t("errors.readonly_admin_required")}
          </div>
        )}

        <button type="submit" disabled={form.submitting} className="btn-primary" style={submitButtonStyle}>
          {form.submitting ? t("login.submitting") : t("login.submit")}
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "2px 0" }}>
          <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
          <span style={{ fontSize: 11, color: "var(--muted)" }}>{t("common.or")}</span>
          <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
        </div>
        <button type="button" onClick={onEnterDemo} className="btn-outline" style={demoButtonStyle}>
          {t("demo.button")}
        </button>

        <div style={{ fontSize: 12, color: "var(--muted)", textAlign: "center" }}>{t("login.footnote")}</div>
      </div>
    </form>
  );
}

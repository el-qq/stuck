"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { LoginFieldErrors } from "@/hooks/useLoginForm";
import { errStyle, fieldLabelStyle, inputStyle } from "./loginStyles";

interface Props {
  server: string;
  loginName: string;
  password: string;
  showPassword: boolean;
  ngfwPort: number | null;
  defaultServerLocked: boolean;
  fieldErrors: LoginFieldErrors;
  roHintDismissed: boolean;
  onServerChange: (value: string) => void;
  onLoginChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onTogglePassword: () => void;
  onDismissRoHint: () => void;
}

/** Presentational server, login and password controls for the login card. */
export function LoginCredentials({
  server,
  loginName,
  password,
  showPassword,
  ngfwPort,
  defaultServerLocked,
  fieldErrors,
  roHintDismissed,
  onServerChange,
  onLoginChange,
  onPasswordChange,
  onTogglePassword,
  onDismissRoHint,
}: Props) {
  const { t } = useI18n();

  return (
    <>
      <label style={fieldLabelStyle}>
        {t("login.serverLabel")}
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input
            value={server}
            onChange={(event) => onServerChange(event.target.value)}
            disabled={defaultServerLocked}
            placeholder={t("login.serverPlaceholder")}
            className="form-control mono"
            style={{
              ...inputStyle,
              flex: 1,
              paddingRight: ngfwPort !== null ? 64 : 12,
              ...(defaultServerLocked && {
                background: "var(--skip-soft)",
                color: "var(--muted)",
                cursor: "not-allowed",
                opacity: 1,
              }),
            }}
            autoComplete="off"
            spellCheck={false}
          />
          {ngfwPort !== null && (
            <span
              className="mono"
              style={{
                position: "absolute",
                right: 10,
                fontSize: 13,
                color: "var(--muted)",
                pointerEvents: "none",
              }}
            >
              :{ngfwPort}
            </span>
          )}
        </div>
        {fieldErrors.server && <span style={errStyle}>{fieldErrors.server}</span>}
      </label>

      <label style={fieldLabelStyle}>
        {t("login.loginLabel")}
        <input
          value={loginName}
          onChange={(event) => onLoginChange(event.target.value)}
          placeholder={t("login.loginPlaceholder")}
          className="form-control"
          style={inputStyle}
          autoComplete="username"
        />
        {fieldErrors.login && <span style={errStyle}>{fieldErrors.login}</span>}
      </label>

      {!roHintDismissed && (
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 8,
            fontSize: 12.5,
            color: "var(--accent)",
            background: "var(--accent-soft)",
            borderRadius: "var(--radius-sm)",
            padding: "10px 12px",
            marginTop: -6,
            lineHeight: 1.45,
          }}
        >
          <span aria-hidden="true" style={{ fontWeight: 700 }}>
            ⓘ
          </span>
          <span style={{ flex: 1 }}>{t("login.readonlyHint")}</span>
          <button
            type="button"
            onClick={onDismissRoHint}
            style={{
              alignSelf: "center",
              background: "none",
              border: "1px solid currentColor",
              borderRadius: "var(--radius-sm)",
              color: "inherit",
              cursor: "pointer",
              fontSize: 12,
              fontWeight: 600,
              padding: "3px 10px",
            }}
          >
            {t("common.ok")}
          </button>
        </div>
      )}

      <label style={fieldLabelStyle}>
        {t("login.passwordLabel")}
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(event) => onPasswordChange(event.target.value)}
            placeholder={t("login.passwordPlaceholder")}
            className="form-control"
            style={{ ...inputStyle, flex: 1, paddingRight: 42 }}
            autoComplete="current-password"
          />
          <button
            type="button"
            onClick={onTogglePassword}
            aria-label={showPassword ? t("login.hidePassword") : t("login.showPassword")}
            aria-pressed={showPassword}
            style={{
              position: "absolute",
              right: 6,
              background: "none",
              border: "none",
              cursor: "pointer",
              padding: "4px 6px",
              fontSize: 15,
              color: "var(--muted)",
              lineHeight: 1,
            }}
          >
            {showPassword ? "🙈" : "👁"}
          </button>
        </div>
        {fieldErrors.password && <span style={errStyle}>{fieldErrors.password}</span>}
      </label>
    </>
  );
}

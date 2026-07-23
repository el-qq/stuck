"use client";

import React, { useEffect, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useI18n } from "@/i18n";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { toApiError } from "@/lib/errors";
import * as api from "@/lib/api";
import { isValidServerFormat } from "@/lib/validate";
import { getLastServer, setLastServer } from "@/lib/storage";
import { Header } from "./Header";
import { SettingsModal } from "./SettingsModal";
import { usePublicConfig } from "@/contexts/PublicConfigContext";

// Non-secret UI preference: the read-only-account hint was dismissed with OK.
// A plain JS-readable cookie (not HttpOnly) — it carries no session data.
const RO_HINT_DISMISSED_COOKIE = "stuck_ro_hint_dismissed";
const RO_HINT_COOKIE_MAX_AGE = 60 * 60 * 24 * 365; // 1 year

function isRoHintDismissed(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie.split("; ").includes(`${RO_HINT_DISMISSED_COOKIE}=1`);
}

export function LoginScreen({ onEnterDemo }: { onEnterDemo: () => void }) {
  const session = useSession();
  const { t } = useI18n();
  const { defaultServer } = usePublicConfig();
  const errorMessage = useApiErrorMessage();

  const [server, setServer] = useState("");
  const [loginName, setLoginName] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<{ server?: string; login?: string; password?: string }>({});
  const [apiErrorText, setApiErrorText] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  // Iteration 3 (#3): actual NGFW connection port, from GET /api/health
  // (contract v2.2, optional field — absent on older backends).
  const [ngfwPort, setNgfwPort] = useState<number | null>(null);
  const [unrestrictedNgfw, setUnrestrictedNgfw] = useState(false);
  const [roHintDismissed, setRoHintDismissed] = useState(isRoHintDismissed);

  function dismissRoHint() {
    document.cookie = `${RO_HINT_DISMISSED_COOKIE}=1; Max-Age=${RO_HINT_COOKIE_MAX_AGE}; ` + `Path=/; SameSite=Lax`;
    setRoHintDismissed(true);
  }

  const defaultServerLocked = defaultServer.length > 0;

  useEffect(() => {
    if (defaultServerLocked) {
      setServer(defaultServer);
      return;
    }
    const last = getLastServer();
    if (last) setServer(last);
  }, [defaultServer, defaultServerLocked]);

  useEffect(() => {
    let cancelled = false;
    void api
      .health()
      .then((h) => {
        if (cancelled) return;
        if (typeof h.ngfw_port === "number") setNgfwPort(h.ngfw_port);
        setUnrestrictedNgfw(h.ngfw_access_mode === "unrestricted");
      })
      .catch(() => {
        // Backend down or old backend without the field — show nothing.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // v2.1: when the NGFW session expired, re-fill server+login from the
  // expired session so the admin only re-enters the password. The inline
  // notice below explains why (localized); it stays until re-login succeeds.
  useEffect(() => {
    if (session.prefill) {
      setServer(defaultServerLocked ? defaultServer : session.prefill.server);
      setLoginName(session.prefill.login);
      setPassword("");
    }
  }, [defaultServer, defaultServerLocked, session.prefill]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const errs: typeof fieldErrors = {};
    if (!server.trim()) errs.server = t("login.validation.serverRequired");
    else if (!isValidServerFormat(server)) errs.server = t("login.validation.serverFormat");
    if (!loginName.trim()) errs.login = t("login.validation.loginRequired");
    if (!password) errs.password = t("login.validation.passwordRequired");
    setFieldErrors(errs);
    if (Object.keys(errs).length > 0) return;

    setApiErrorText(null);
    setSubmitting(true);
    try {
      // On a 2FA account this sets the session context's twoFactorPending, and
      // App swaps in the code form; otherwise the session becomes authenticated.
      await session.login(loginName.trim(), password, server.trim());
      // Iteration 3 (#1): remember the last successfully used server address.
      setLastServer(server.trim());
    } catch (err) {
      const apiErr = toApiError(err);
      setApiErrorText(errorMessage(apiErr));
      // FR-1: on invalid credentials, clear the password only.
      if (apiErr.code === "invalid_credentials") {
        setPassword("");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="app-shell">
      {/* Iteration 3 (#10): topbar is always visible; on the login screen it
          has no session-dependent items (no refresh/logout/rules status). */}
      <Header anonymous onOpenSettings={() => setSettingsOpen(true)} />

      <div
        className="login-main"
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 24,
        }}
      >
        <form
          className="login-card"
          onSubmit={handleSubmit}
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

          {/* v2.1: stale NGFW session on the backend — explain the re-login. */}
          {session.expiredNotice && (
            <div role="alert" style={warnBlockStyle}>
              {t("login.sessionExpiredNotice")}
            </div>
          )}

          {session.bootstrapError && (
            <div role="alert" style={warnBlockStyle}>
              {errorMessage(session.bootstrapError)}
            </div>
          )}

          {unrestrictedNgfw && (
            <div role="alert" style={warnBlockStyle}>
              {t("login.unrestrictedNgfwWarning")}
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <label style={fieldLabelStyle}>
              {t("login.serverLabel")}
              <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                <input
                  value={server}
                  onChange={(e) => setServer(e.target.value)}
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
                {/* Iteration 3 (#3): actual connection port from the backend. */}
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
                onChange={(e) => setLoginName(e.target.value)}
                placeholder={t("login.loginPlaceholder")}
                className="form-control"
                style={inputStyle}
                autoComplete="username"
              />
              {fieldErrors.login && <span style={errStyle}>{fieldErrors.login}</span>}
            </label>

            {/* Recommend a read-only administrator account — shown right
                where the admin decides which account to type. OK hides it;
                the choice persists via a non-secret cookie. */}
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
                  onClick={dismissRoHint}
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
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t("login.passwordPlaceholder")}
                  className="form-control"
                  style={{ ...inputStyle, flex: 1, paddingRight: 42 }}
                  autoComplete="current-password"
                />
                {/* Iteration 3 (#2): password visibility toggle. */}
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
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

            {apiErrorText && (
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
                {apiErrorText}
              </div>
            )}

            {/* Shown between the password and the button after a 2FA reset
                (too many wrong codes / NGFW account lockout). */}
            {session.twoFactorResetNotice && (
              <div role="alert" style={warnBlockStyle}>
                {t("login.twoFactorResetNotice")}
              </div>
            )}

            {/* Optional STUCK_REQUIRE_READONLY_ADMIN policy rejected a
                verified non-read-only role (from a plain login or after a
                2FA code was accepted). No session/cookie was created. */}
            {session.readonlyAdminRequiredNotice && (
              <div role="alert" style={warnBlockStyle}>
                {t("errors.readonly_admin_required")}
              </div>
            )}

            <button type="submit" disabled={submitting} className="btn-primary" style={submitBtnStyle}>
              {submitting ? t("login.submitting") : t("login.submit")}
            </button>

            {/* Iteration 4: enter the fully offline demo, no backend/login. */}
            <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "2px 0" }}>
              <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
              <span style={{ fontSize: 11, color: "var(--muted)" }}>{t("common.or")}</span>
              <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
            </div>
            <button type="button" onClick={onEnterDemo} className="btn-outline" style={demoBtnStyle}>
              {t("demo.button")}
            </button>

            <div style={{ fontSize: 12, color: "var(--muted)", textAlign: "center" }}>{t("login.footnote")}</div>
          </div>
        </form>
      </div>

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

const warnBlockStyle: React.CSSProperties = {
  fontSize: 12.5,
  color: "var(--warn)",
  background: "var(--warn-soft)",
  borderRadius: "var(--radius-sm)",
  padding: "10px 12px",
  marginBottom: 14,
  lineHeight: 1.45,
};

const fieldLabelStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 6,
  fontSize: 12.5,
  fontWeight: 600,
  color: "var(--muted)",
};

const inputStyle: React.CSSProperties = {
  border: "1px solid var(--line)",
  background: "var(--panel2)",
  color: "var(--text)",
  borderRadius: "var(--radius-sm)",
  padding: "10px 12px",
  fontSize: 14,
  width: "100%",
};

const errStyle: React.CSSProperties = {
  fontSize: 11.5,
  color: "var(--bad)",
  fontWeight: 600,
};

const submitBtnStyle: React.CSSProperties = {
  marginTop: 8,
  borderRadius: "var(--radius-sm)",
  padding: 12,
  fontSize: 14.5,
  fontWeight: 600,
};

const demoBtnStyle: React.CSSProperties = {
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 600,
};

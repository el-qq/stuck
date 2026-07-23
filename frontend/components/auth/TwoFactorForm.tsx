"use client";

import React, { useEffect, useState } from "react";
import { useI18n } from "@/i18n";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import { toApiError } from "@/lib/errors";
import * as api from "@/lib/api";

/**
 * Second-factor (2FA) code entry, shown BEFORE the main screen once
 * `login()` resolved to `{ twoFactorRequired: true }`. Mobile-friendly and
 * visually consistent with LoginScreen (same card, inputs >= 16px, no
 * horizontal scroll). See docs/source/mfa2-plan.md §Требования.
 *
 * Contract of the flow (docs/API_CONTRACT.md):
 *   - `submit2fa(code)` succeeds → `onSuccess()`; the parent finalizes the session.
 *   - throws `second_factor_invalid` (details.can_retry === true) → stay on the
 *     form, show the error, let the admin retry.
 *   - throws `second_factor_invalid` (can_retry === false) or
 *     `second_factor_expired` → the challenge is dead; call `onExpired()`.
 *   - the countdown reaching `expiresAt` auto-cancels (`cancel2fa()` then
 *     `onExpired()`), matching the backend TTL (STUCK_2FA_TTL_SECONDS).
 *   - throws `readonly_admin_required` (optional STUCK_REQUIRE_READONLY_ADMIN
 *     policy; the code was accepted but the role is not read-only) → the
 *     backend already dropped the challenge, so this is treated the same as
 *     an expired challenge: call `onReadonlyRequired()` to return to login.
 */
export interface TwoFactorFormProps {
  /** ISO-8601 UTC instant the challenge expires; drives the countdown. */
  expiresAt: string;
  /** Optional NGFW-provided hint to render above the input (may be empty). */
  message?: string | null;
  /** Called after a code is accepted; the parent finalizes the session. */
  onSuccess: () => void | Promise<void>;
  /** Involuntary end (countdown reached zero, or the backend reset the
   *  challenge after too many attempts) — parent → login with an explanation. */
  onExpired: () => void;
  /** The accepted code's role was rejected by the optional read-only-admin
   *  login policy (`readonly_admin_required`) — parent → login with that
   *  explanation. */
  onReadonlyRequired: () => void;
  /** The admin pressed Cancel — parent → login without a notice. */
  onCancel: () => void;
}

/** Whole seconds left until `expiresAt` (never negative). */
function secondsUntil(expiresAt: string): number {
  const ms = new Date(expiresAt).getTime() - Date.now();
  return Number.isFinite(ms) ? Math.max(0, Math.round(ms / 1000)) : 0;
}

export function TwoFactorForm({ expiresAt, message, onSuccess, onExpired, onReadonlyRequired, onCancel }: TwoFactorFormProps) {
  const { t } = useI18n();
  const errorMessage = useApiErrorMessage();

  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [apiErrorText, setApiErrorText] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState<number>(() => secondsUntil(expiresAt));

  useEffect(() => {
    setSecondsLeft(secondsUntil(expiresAt));
    const id = window.setInterval(() => {
      const left = secondsUntil(expiresAt);
      setSecondsLeft(left);
      if (left <= 0) {
        window.clearInterval(id);
        // Hand back to the parent, which cancels the challenge and returns to login.
        onExpired();
      }
    }, 1000);
    return () => window.clearInterval(id);
  }, [expiresAt, onExpired]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = code.trim();
    if (!trimmed) {
      setFieldError(t("twoFactor.validation.codeRequired"));
      return;
    }
    setFieldError(null);
    setSubmitting(true);
    setApiErrorText(null);
    try {
      await api.submit2fa(trimmed);
      await onSuccess();
    } catch (err) {
      const apiErr = toApiError(err);
      if (apiErr.code === "second_factor_expired") {
        // The challenge is over — NGFW stopped accepting codes or the window
        // expired. Reset to the login screen.
        onExpired();
      } else if (apiErr.code === "readonly_admin_required") {
        // The code was correct, but the optional read-only-admin-only login
        // policy rejected the verified role. The backend already closed the
        // challenge and the provisional NGFW session — reset to login.
        onReadonlyRequired();
      } else {
        // Wrong code (second_factor_invalid): stay and let the admin retry.
        setApiErrorText(errorMessage(apiErr));
        setCode("");
      }
    } finally {
      setSubmitting(false);
    }
  }

  function handleCancel() {
    // Voluntary cancel — no "reset" notice on the login screen.
    onCancel();
  }

  return (
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
      <div style={{ fontSize: 17, fontWeight: 700 }}>{t("twoFactor.title")}</div>
      <div style={{ fontSize: 12.5, color: "var(--muted)", marginTop: 6, lineHeight: 1.45 }}>{message || t("twoFactor.subtitle")}</div>

      <div style={{ height: 1, background: "var(--line)", margin: "20px 0 24px" }} />

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <label style={fieldLabelStyle}>
          {t("twoFactor.codeLabel")}
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            placeholder={t("twoFactor.codePlaceholder")}
            className="form-control mono"
            style={inputStyle}
          />
          {fieldError && <span style={errStyle}>{fieldError}</span>}
        </label>

        <div role="timer" aria-live="polite" style={{ fontSize: 12.5, color: secondsLeft <= 15 ? "var(--warn)" : "var(--muted)" }}>
          {t("twoFactor.expiresIn", { seconds: secondsLeft })}
        </div>

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

        <button type="submit" disabled={submitting || secondsLeft <= 0} className="btn-primary" style={submitBtnStyle}>
          {submitting ? t("twoFactor.submitting") : t("twoFactor.submit")}
        </button>
        <button type="button" onClick={handleCancel} disabled={submitting} className="btn-outline" style={cancelBtnStyle}>
          {t("twoFactor.cancel")}
        </button>
      </div>
    </form>
  );
}

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
  // >= 16px keeps iOS from zooming the field on focus (mobile requirement).
  padding: "11px 12px",
  fontSize: 16,
  width: "100%",
  letterSpacing: "0.12em",
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

const cancelBtnStyle: React.CSSProperties = {
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 600,
};

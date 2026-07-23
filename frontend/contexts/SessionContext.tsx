"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { AdminAccessProfile, SessionStatus } from "@/lib/types";

type AuthStatus = "checking" | "authenticated" | "anonymous";

/** Backend-held 2FA challenge the browser must resolve before it is authenticated.
 *  Owned here (not by a screen) so a page reload can restore it from the server. */
export type TwoFactorPending = { expiresAt: string; message: string | null };

interface SessionContextValue {
  status: AuthStatus;
  session: SessionStatus | null;
  /** Non-null while a 2FA code is required (fresh login OR restored on reload).
   *  The app renders the code form whenever this is set. */
  twoFactorPending: TwoFactorPending | null;
  /** Set when the initial GET /api/session call itself failed for a reason
   *  other than "not logged in" (e.g. our backend is unreachable). Shown as
   *  a banner on the login screen instead of silently failing. */
  bootstrapError: ApiError | null;
  /** Set right after a request comes back 401 session_expired. Contract
   *  v2.1: this means the backend's NGFW session for the pair went stale —
   *  the login form shows a localized explanation and asks to re-enter the
   *  password. Cleared on successful re-login. */
  expiredNotice: boolean;
  clearExpiredNotice: () => void;
  /** v2.1: identity of the session that just expired — the login form
   *  re-fills the server and login fields from it, so the admin only
   *  re-enters the password. Null when there was no known session. */
  prefill: { login: string; server: string } | null;
  /** Sign in. On a 2FA-required account this sets {@link twoFactorPending} (the
   *  app then shows the code form); otherwise the session becomes authenticated. */
  login: (login: string, password: string, server: string) => Promise<void>;
  /** Finalize the session after a 2FA code was accepted (mirrors login success). */
  completeTwoFactor: () => Promise<void>;
  /** Abandon the in-flight 2FA challenge and return to the login screen. Pass
   *  `{ notice: true }` for an involuntary reset (too many attempts / expired)
   *  so the login screen explains it; `{ readonlyRequired: true }` for the
   *  optional read-only-admin-only login policy rejecting the verified role
   *  (contract `readonly_admin_required`, same treatment as an expired
   *  challenge). The identity is always preserved. */
  cancelTwoFactor: (opts?: { notice?: boolean; readonlyRequired?: boolean }) => Promise<void>;
  /** True after an involuntary 2FA reset; the login screen shows a hint. */
  twoFactorResetNotice: boolean;
  clearTwoFactorResetNotice: () => void;
  /** True after login/2FA was rejected because the optional
   *  STUCK_REQUIRE_READONLY_ADMIN policy only accepts the read-only role; the
   *  login screen shows the `errors.readonly_admin_required` message. */
  readonlyAdminRequiredNotice: boolean;
  clearReadonlyAdminRequiredNotice: () => void;
  logout: () => Promise<void>;
  /** v2 (FR-2.5): record that the pair's rules snapshot is loaded and when. */
  markRulesUpdated: (rulesUpdatedAt: string) => void;
  /** Re-evaluate the server-side NGFW role for the active session. */
  refreshAccessProfile: () => Promise<AdminAccessProfile>;
  /** Call from any catch block. Returns true if this was an auth error and
   *  the session was reset accordingly (caller does not need to show its own
   *  error message in that case). */
  handleAuthError: (err: unknown) => boolean;
}

const SessionContext = createContext<SessionContextValue | null>(null);

const LAST_IDENTITY_KEY = "stuck.lastIdentity";
type StoredIdentity = { login: string; server: string };

function readLastIdentity(): StoredIdentity | null {
  if (typeof window === "undefined") return null;
  try {
    const value: unknown = JSON.parse(window.localStorage.getItem(LAST_IDENTITY_KEY) ?? "null");
    if (
      typeof value === "object" &&
      value !== null &&
      typeof (value as Record<string, unknown>).login === "string" &&
      typeof (value as Record<string, unknown>).server === "string"
    ) {
      return value as StoredIdentity;
    }
  } catch {
    // Treat malformed or unavailable browser storage as no prior identity.
  }
  return null;
}

function rememberIdentity(identity: StoredIdentity): void {
  try {
    window.localStorage.setItem(LAST_IDENTITY_KEY, JSON.stringify(identity));
  } catch {
    // The re-login flow remains functional without the convenience prefill.
  }
}

function forgetIdentity(): void {
  try {
    window.localStorage.removeItem(LAST_IDENTITY_KEY);
  } catch {
    // ignore unavailable browser storage
  }
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("checking");
  const [session, setSession] = useState<SessionStatus | null>(null);
  const [bootstrapError, setBootstrapError] = useState<ApiError | null>(null);
  const [expiredNotice, setExpiredNotice] = useState(false);
  const [prefill, setPrefill] = useState<{ login: string; server: string } | null>(null);
  const [twoFactorPending, setTwoFactorPending] = useState<TwoFactorPending | null>(null);
  // True after a 2FA challenge was reset to login involuntarily (too many wrong
  // codes / locked / expired) — the login screen explains why. Cleared on the
  // next successful auth or when the notice is dismissed.
  const [twoFactorResetNotice, setTwoFactorResetNotice] = useState(false);
  // True after login (or 2FA) was rejected under the optional
  // STUCK_REQUIRE_READONLY_ADMIN policy — the login screen explains why.
  // Cleared on the next successful auth or when the notice is dismissed.
  const [readonlyAdminRequiredNotice, setReadonlyAdminRequiredNotice] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .getSession()
      .then((s) => {
        if (cancelled) return;
        if ("twoFactorPending" in s) {
          // The page was reloaded mid-2FA; restore the code form from the
          // backend-held challenge instead of dropping to a fresh login.
          setTwoFactorPending({ expiresAt: s.expiresAt, message: null });
          setStatus("anonymous");
          return;
        }
        rememberIdentity({ login: s.login, server: s.server });
        setSession(s);
        setStatus("authenticated");
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const err = toApiError(e);
        const lastIdentity = readLastIdentity();
        if (err.code === "not_authenticated") {
          setStatus("anonymous");
          // The browser may have already discarded an expired HttpOnly cookie,
          // so the backend cannot distinguish it from a missing one. A stored
          // non-secret identity lets the UI still present the password re-login
          // flow after a normal STUCK-session expiry or backend restart.
          if (lastIdentity) {
            setPrefill(lastIdentity);
            setExpiredNotice(true);
          }
        } else if (err.code === "session_expired") {
          setStatus("anonymous");
          setExpiredNotice(true);
          if (lastIdentity) setPrefill(lastIdentity);
        } else {
          setStatus("anonymous");
          setBootstrapError(err);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const finalizeSession = useCallback(async () => {
    // Re-fetch canonical status (rules_loaded / rules_updated_at etc.) rather
    // than guessing from the login response, since rule-set loading may happen
    // lazily. After a re-login of a cached pair (first_login=false) this keeps
    // the previous rules_updated_at visible, per contract §5.1.
    const s = await api.getSession();
    if ("twoFactorPending" in s) {
      // Shouldn't happen right after a successful auth, but stay safe.
      setTwoFactorPending({ expiresAt: s.expiresAt, message: null });
      setStatus("anonymous");
      return;
    }
    rememberIdentity({ login: s.login, server: s.server });
    setSession(s);
    setStatus("authenticated");
    setBootstrapError(null);
    setExpiredNotice(false);
    setPrefill(null);
    setTwoFactorPending(null);
    setTwoFactorResetNotice(false);
    setReadonlyAdminRequiredNotice(false);
  }, []);

  const login = useCallback(
    async (loginName: string, password: string, server: string): Promise<void> => {
      const outcome = await api.login({ login: loginName, password, server });
      if (outcome.twoFactorRequired) {
        // Backend set the HttpOnly stuck_2fa cookie; surface the code form via
        // context state so a reload can restore it too. No session exists yet.
        // Remember the identity now so a reset back to login only re-asks for
        // the password (and a page reload can still prefill it).
        rememberIdentity({ login: loginName, server });
        setTwoFactorResetNotice(false);
        setReadonlyAdminRequiredNotice(false);
        setTwoFactorPending({ expiresAt: outcome.expiresAt, message: outcome.message ?? null });
        setStatus("anonymous");
        return;
      }
      await finalizeSession();
    },
    [finalizeSession],
  );

  const completeTwoFactor = useCallback(async () => {
    // The code was accepted; the backend swapped stuck_2fa for stuck_session.
    setTwoFactorPending(null);
    setTwoFactorResetNotice(false);
    setReadonlyAdminRequiredNotice(false);
    await finalizeSession();
  }, [finalizeSession]);

  const cancelTwoFactor = useCallback(async (opts?: { notice?: boolean; readonlyRequired?: boolean }) => {
    try {
      await api.cancel2fa();
    } catch {
      // Idempotent on the backend; drop the form regardless (the backend
      // already dropped the pending challenge itself on readonly_admin_required).
    }
    setTwoFactorPending(null);
    setStatus("anonymous");
    // Preserve the login/server so re-authentication only needs the password.
    const identity = readLastIdentity();
    if (identity) setPrefill(identity);
    setTwoFactorResetNotice(opts?.notice === true);
    setReadonlyAdminRequiredNotice(opts?.readonlyRequired === true);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setSession(null);
      setStatus("anonymous");
      setExpiredNotice(false);
      setPrefill(null);
      forgetIdentity();
    }
  }, []);

  const markRulesUpdated = useCallback((rulesUpdatedAt: string) => {
    setSession((prev) => (prev ? { ...prev, rules_loaded: true, rules_updated_at: rulesUpdatedAt } : prev));
  }, []);

  const refreshAccessProfile = useCallback(async (): Promise<AdminAccessProfile> => {
    const result = await api.refreshAccessProfile();
    setSession((prev) => (prev ? { ...prev, access_profile: result.access_profile } : prev));
    return result.access_profile;
  }, []);

  const handleAuthError = useCallback(
    (err: unknown): boolean => {
      const apiErr = toApiError(err);
      if (apiErr.code === "session_expired" || apiErr.code === "not_authenticated") {
        // v2.1: keep the expired session's identity so the login form can
        // re-fill server+login and the admin only re-types the password.
        const identity = session ? { login: session.login, server: session.server } : readLastIdentity();
        if (identity && apiErr.code === "session_expired") {
          rememberIdentity(identity);
          setPrefill(identity);
        }
        setSession(null);
        setStatus("anonymous");
        setExpiredNotice(apiErr.code === "session_expired");
        return true;
      }
      return false;
    },
    [session],
  );

  const clearExpiredNotice = useCallback(() => setExpiredNotice(false), []);
  const clearTwoFactorResetNotice = useCallback(() => setTwoFactorResetNotice(false), []);
  const clearReadonlyAdminRequiredNotice = useCallback(() => setReadonlyAdminRequiredNotice(false), []);

  const value = useMemo(
    () => ({
      status,
      session,
      twoFactorPending,
      twoFactorResetNotice,
      clearTwoFactorResetNotice,
      readonlyAdminRequiredNotice,
      clearReadonlyAdminRequiredNotice,
      bootstrapError,
      expiredNotice,
      clearExpiredNotice,
      prefill,
      login,
      completeTwoFactor,
      cancelTwoFactor,
      logout,
      markRulesUpdated,
      refreshAccessProfile,
      handleAuthError,
    }),
    [
      status,
      session,
      twoFactorPending,
      twoFactorResetNotice,
      readonlyAdminRequiredNotice,
      clearReadonlyAdminRequiredNotice,
      clearTwoFactorResetNotice,
      bootstrapError,
      expiredNotice,
      clearExpiredNotice,
      prefill,
      login,
      completeTwoFactor,
      cancelTwoFactor,
      logout,
      markRulesUpdated,
      refreshAccessProfile,
      handleAuthError,
    ],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within SessionProvider");
  return ctx;
}

"use client";

import React, { useEffect, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useI18n } from "@/i18n";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { toApiError } from "@/lib/errors";
import { getLastServer, setLastServer } from "@/lib/storage";
import { isValidServerFormat } from "@/lib/validate";

const RO_HINT_DISMISSED_COOKIE = "stuck_ro_hint_dismissed";
const RO_HINT_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

export interface LoginFieldErrors {
  server?: string;
  login?: string;
  password?: string;
}

/** State and side effects behind the password-login form.
 *
 * This hook keeps secret form data within the React tree and limits browser
 * persistence to the last non-secret server address and a non-secret hint
 * preference. It intentionally never reads, stores or exposes session cookies.
 */
export function useLoginForm(defaultServer: string) {
  const session = useSession();
  const { t } = useI18n();
  const errorMessage = useApiErrorMessage();
  const [server, setServer] = useState("");
  const [loginName, setLoginName] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<LoginFieldErrors>({});
  const [apiErrorText, setApiErrorText] = useState<string | null>(null);
  const [ngfwPort, setNgfwPort] = useState<number | null>(null);
  const [unrestrictedNgfw, setUnrestrictedNgfw] = useState(false);
  const [roHintDismissed, setRoHintDismissed] = useState(isRoHintDismissed);
  const defaultServerLocked = defaultServer.length > 0;

  useEffect(() => {
    if (defaultServerLocked) {
      setServer(defaultServer);
      return;
    }
    const lastServer = getLastServer();
    if (lastServer) setServer(lastServer);
  }, [defaultServer, defaultServerLocked]);

  useEffect(() => {
    let cancelled = false;
    void api
      .health()
      .then((health) => {
        if (cancelled) return;
        if (typeof health.ngfw_port === "number") setNgfwPort(health.ngfw_port);
        setUnrestrictedNgfw(health.ngfw_access_mode === "unrestricted");
      })
      .catch(() => {
        // The login form remains usable when the initial health probe fails.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!session.prefill) return;
    setServer(defaultServerLocked ? defaultServer : session.prefill.server);
    setLoginName(session.prefill.login);
    setPassword("");
  }, [defaultServer, defaultServerLocked, session.prefill]);

  function dismissRoHint() {
    document.cookie = `${RO_HINT_DISMISSED_COOKIE}=1; Max-Age=${RO_HINT_COOKIE_MAX_AGE}; Path=/; SameSite=Lax`;
    setRoHintDismissed(true);
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const errors: LoginFieldErrors = {};
    if (!server.trim()) errors.server = t("login.validation.serverRequired");
    else if (!isValidServerFormat(server)) errors.server = t("login.validation.serverFormat");
    if (!loginName.trim()) errors.login = t("login.validation.loginRequired");
    if (!password) errors.password = t("login.validation.passwordRequired");
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;

    setApiErrorText(null);
    setSubmitting(true);
    try {
      await session.login(loginName.trim(), password, server.trim());
      setLastServer(server.trim());
    } catch (error) {
      const apiError = toApiError(error);
      setApiErrorText(errorMessage(apiError));
      if (apiError.code === "invalid_credentials") setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  return {
    server,
    setServer,
    loginName,
    setLoginName,
    password,
    setPassword,
    showPassword,
    setShowPassword,
    togglePassword: () => setShowPassword((visible) => !visible),
    submitting,
    fieldErrors,
    apiErrorText,
    ngfwPort,
    unrestrictedNgfw,
    roHintDismissed,
    dismissRoHint,
    defaultServerLocked,
    expiredNotice: session.expiredNotice,
    bootstrapErrorText: session.bootstrapError ? errorMessage(session.bootstrapError) : null,
    twoFactorResetNotice: session.twoFactorResetNotice,
    readonlyAdminRequiredNotice: session.readonlyAdminRequiredNotice,
    handleSubmit,
  };
}

export type LoginFormController = ReturnType<typeof useLoginForm>;

function isRoHintDismissed(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie.split("; ").includes(`${RO_HINT_DISMISSED_COOKIE}=1`);
}

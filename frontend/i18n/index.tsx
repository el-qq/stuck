"use client";

import React, { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useState } from "react";
import { en, MessageKey } from "./en";
import { DEFAULT_LOCALE, DICTIONARIES, matchLocale, resolveLocale, type Locale } from "./locales";

export { SUPPORTED_LOCALES, DEFAULT_LOCALE, LOCALE_REGION_ORDER, matchLocale, resolveLocale } from "./locales";
export type { Locale, LocaleDescriptor, LocaleRegion, LocaleTier } from "./locales";
export { CORE_MESSAGE_KEYS } from "./core";
export type { CoreDictionary, CoreMessageKey, FullDictionary, LocaleDictionary } from "./core";

const LOCALE_STORAGE_KEY = "stuck.locale";

/** FR-6.3: initial language guess from the browser, falling back to English. */
function detectBrowserLocale(): Locale {
  if (typeof navigator === "undefined") return DEFAULT_LOCALE;
  const candidates = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language];
  return resolveLocale(candidates) ?? DEFAULT_LOCALE;
}

function readStoredLocale(): Locale | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    // Matched, not compared: a value stored before a regional dictionary
    // existed ("pt") still resolves to the locale that now serves it.
    if (stored) return matchLocale(stored);
  } catch {
    // localStorage may be unavailable (private mode, disabled storage) — ignore.
  }
  return null;
}

type Vars = Record<string, string | number>;

interface I18nContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: MessageKey, vars?: Vars) => string;
  /** Translate a *server-supplied* key (title_key/reason_key) with a safe fallback to the raw key. */
  tOptional: (key: string | undefined | null, vars?: Vars) => string | null;
}

const I18nContext = createContext<I18nContextValue | null>(null);

function interpolate(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const v = vars[name];
    return v === undefined ? match : String(v);
  });
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  // Start with the deterministic server value, then select the browser language
  // before the first client paint. This avoids briefly showing English to a
  // browser whose preferred language is one of our supported locales.
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);

  useLayoutEffect(() => {
    const initial = readStoredLocale() ?? detectBrowserLocale();
    setLocaleState(initial);
  }, []);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      // ignore storage failures
    }
  }, []);

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.lang = locale;
    }
  }, [locale]);

  const dict = DICTIONARIES[locale];

  // Core-tier locales (see core.ts) translate the core key set and may omit
  // the rest, so every lookup falls back to English before giving up on the
  // raw key. This is the mechanism that makes a partial locale shippable.
  const t = useCallback((key: MessageKey, vars?: Vars) => interpolate(dict[key] ?? en[key] ?? key, vars), [dict]);

  const tOptional = useCallback(
    (key: string | undefined | null, vars?: Vars) => {
      if (!key) return null;
      const table = dict as Record<string, string | undefined>;
      const fallbackTable = en as unknown as Record<string, string | undefined>;
      const value = table[key] ?? fallbackTable[key];
      if (value) return interpolate(value, vars);
      return null;
    },
    [dict],
  );

  const value = useMemo(() => ({ locale, setLocale, t, tOptional }), [locale, setLocale, t, tOptional]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}

export type { MessageKey };

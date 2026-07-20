"use client";

import React, { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useState } from "react";
import { en, MessageKey } from "./en";
import { es } from "./es";
import { ru } from "./ru";
import { kk } from "./kk";
import { ms } from "./ms";
import { fr } from "./fr";
import { be } from "./be";
import { ky } from "./ky";
import { hy } from "./hy";

export type Locale = "en" | "es" | "ru" | "kk" | "ms" | "fr" | "be" | "ky" | "hy";

export const SUPPORTED_LOCALES: readonly { code: Locale; nativeName: string }[] = [
  { code: "en", nativeName: "English" },
  { code: "es", nativeName: "Español" },
  { code: "ru", nativeName: "Русский" },
  { code: "kk", nativeName: "Қазақша" },
  { code: "ms", nativeName: "Bahasa Melayu" },
  { code: "fr", nativeName: "Français" },
  { code: "be", nativeName: "Беларуская" },
  { code: "ky", nativeName: "Кыргызча" },
  { code: "hy", nativeName: "Հայերեն" },
];

const DEFAULT_LOCALE: Locale = "en";
const LOCALE_STORAGE_KEY = "stuck.locale";

const DICTIONARIES: Record<Locale, Record<MessageKey, string>> = { en, es, ru, kk, ms, fr, be, ky, hy };

function isLocale(v: string): v is Locale {
  return (Object.keys(DICTIONARIES) as string[]).includes(v);
}

/** FR-6.3: initial language guess from the browser, falling back to English. */
function detectBrowserLocale(): Locale {
  if (typeof navigator === "undefined") return DEFAULT_LOCALE;
  const candidates = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language];
  for (const raw of candidates) {
    if (!raw) continue;
    const short = raw.slice(0, 2).toLowerCase();
    if (isLocale(short)) return short;
  }
  return DEFAULT_LOCALE;
}

function readStoredLocale(): Locale | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (stored && isLocale(stored)) return stored;
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

  const t = useCallback((key: MessageKey, vars?: Vars) => interpolate(dict[key] ?? en[key] ?? key, vars), [dict]);

  const tOptional = useCallback(
    (key: string | undefined | null, vars?: Vars) => {
      if (!key) return null;
      const table = dict as Record<string, string>;
      const fallbackTable = en as unknown as Record<string, string>;
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

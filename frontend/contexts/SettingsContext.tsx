"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Theme = "light" | "dark";

export interface AccentOption {
  id: string;
  value: string;
  labelKey: string;
}

/** Application-owned preset accent colors. */
export const ACCENT_OPTIONS: readonly AccentOption[] = [
  { id: "blue", value: "#2f6bff", labelKey: "blue" },
  { id: "teal", value: "#0e9384", labelKey: "teal" },
  { id: "violet", value: "#7a5af8", labelKey: "violet" },
  { id: "crimson", value: "#c01048", labelKey: "crimson" },
];

const DEFAULT_THEME: Theme = "light";
const DEFAULT_ACCENT = ACCENT_OPTIONS[0]!.value;

const THEME_KEY = "stuck.theme";
const ACCENT_KEY = "stuck.accent";

function readStoredTheme(): Theme | null {
  if (typeof window === "undefined") return null;
  try {
    const v = window.localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

function readStoredAccent(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(ACCENT_KEY);
  } catch {
    return null;
  }
}

function detectPreferredTheme(): Theme {
  if (typeof window === "undefined" || !window.matchMedia) return DEFAULT_THEME;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

interface SettingsContextValue {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggleTheme: () => void;
  accent: string;
  setAccent: (hex: string) => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  // Deterministic default for SSR/first paint; reconciled with localStorage /
  // prefers-color-scheme right after mount (FR-7.3).
  const [theme, setThemeState] = useState<Theme>(DEFAULT_THEME);
  const [accent, setAccentState] = useState<string>(DEFAULT_ACCENT);

  useEffect(() => {
    setThemeState(readStoredTheme() ?? detectPreferredTheme());
    setAccentState(readStoredAccent() ?? DEFAULT_ACCENT);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    document.documentElement.style.setProperty("--accent", accent);
  }, [accent]);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    try {
      window.localStorage.setItem(THEME_KEY, t);
    } catch {
      // ignore
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => {
      const next: Theme = prev === "light" ? "dark" : "light";
      try {
        window.localStorage.setItem(THEME_KEY, next);
      } catch {
        // ignore
      }
      return next;
    });
  }, []);

  const setAccent = useCallback((hex: string) => {
    setAccentState(hex);
    try {
      window.localStorage.setItem(ACCENT_KEY, hex);
    } catch {
      // ignore
    }
  }, []);

  const value = useMemo(() => ({ theme, setTheme, toggleTheme, accent, setAccent }), [theme, setTheme, toggleTheme, accent, setAccent]);

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings must be used within SettingsProvider");
  return ctx;
}

"use client";

import React, { useLayoutEffect, useRef } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useI18n } from "@/i18n";
import { APP_VERSION } from "@/lib/version";

interface HeaderProps {
  /** Iteration 3 (#10): the topbar is shown on the login screen too, without
   *  session-dependent items (rules status, refresh, logout). */
  anonymous?: boolean;
  rulesLoaded?: boolean;
  /** v2 (FR-2.5): when the pair's rules snapshot was last loaded; null = never. */
  rulesUpdatedAt?: string | null;
  refreshing?: boolean;
  onRefresh?: () => void;
  onOpenSettings: () => void;
  /** Shown only in demo mode to leave the offline workspace. */
  onExitDemo?: () => void;
  /** Demo intentionally mirrors the signed-in header, but backend actions are
   * visibly disabled and never receive callbacks. */
  demoMode?: boolean;
  /** §3.8: render the rules-export button only when the backend
   *  enabled the feature (rules_export_enabled). Authenticated mode only. */
  exportEnabled?: boolean;
  exporting?: boolean;
  onExport?: () => void;
  /** Prevent snapshot actions for a server-confirmed insufficient role. */
  accessAllowed?: boolean;
}

/** UI-locale formatting; omitted timeZone intentionally uses the browser's current zone. */
function formatDateTime(iso: string | null, locale: string): string {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "medium" }).format(new Date(iso));
  } catch {
    return "—";
  }
}

export function Header({
  anonymous = false,
  rulesLoaded = false,
  rulesUpdatedAt = null,
  refreshing = false,
  onRefresh,
  onOpenSettings,
  onExitDemo,
  demoMode = false,
  exportEnabled = false,
  exporting = false,
  onExport,
  accessAllowed = true,
}: HeaderProps) {
  const session = useSession();
  const { t, locale } = useI18n();
  const headerRef = useRef<HTMLElement>(null);
  const showsRules = !anonymous || demoMode;
  const showsIdentity = !anonymous && !demoMode;

  // Publish the real header height (it wraps to more rows on mobile and grows
  // with the tab bar) so sticky panels/scroll margins offset below it exactly.
  useLayoutEffect(() => {
    const el = headerRef.current;
    if (!el) return;
    const apply = () => document.documentElement.style.setProperty("--stuck-header-h", `${el.offsetHeight}px`);
    apply();
    const observer = new ResizeObserver(apply);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <header ref={headerRef} className={`app-header${anonymous ? " app-header--anonymous" : ""}`}>
      <div className="app-header__brand">
        <div className="app-header__mark">ST</div>
        <div className="app-header__title">{t("common.appName")}</div>
        <span className="app-header__version">v{APP_VERSION}</span>
      </div>
      {showsIdentity && (
        <div className="app-header__identity mono" title={session.session ? `${session.session.login}@${session.session.server}` : ""}>
          {session.session ? `${session.session.login}@${session.session.server}` : ""}
        </div>
      )}
      <div className="app-header__spacer" />

      {showsRules && (
        <div className="app-header__rules">
          <span
            aria-hidden="true"
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: rulesLoaded ? "var(--ok)" : "var(--warn)",
              display: "inline-block",
              animation: rulesLoaded ? "none" : "pulse 1.6s ease infinite",
            }}
          />
          {rulesLoaded && rulesUpdatedAt ? t("header.rulesLoaded", { time: formatDateTime(rulesUpdatedAt, locale) }) : t("header.rulesNotLoaded")}
        </div>
      )}

      <div className="app-header__actions">
        {showsRules && (
          <button
            onClick={demoMode ? undefined : onRefresh}
            disabled={demoMode || refreshing || !accessAllowed}
            title={demoMode ? t("demo.backendActionUnavailable") : undefined}
            data-demo-unavailable={demoMode || undefined}
            className="app-header__button btn-soft"
          >
            <span style={{ display: "inline-block", animation: refreshing ? "spin 1s linear infinite" : "none" }}>⟳</span>{" "}
            {refreshing ? t("header.refreshing") : t("header.refresh")}
          </button>
        )}

        {showsRules && exportEnabled && (
          <button
            onClick={demoMode ? undefined : onExport}
            disabled={demoMode || exporting}
            title={demoMode ? t("demo.backendActionUnavailable") : undefined}
            data-demo-unavailable={demoMode || undefined}
            className="app-header__button btn-soft"
          >
            {exporting ? t("header.exporting") : `⬇ ${t("header.exportRules")}`}
          </button>
        )}

        <button onClick={onOpenSettings} title={t("header.settings")} className="app-header__button icon-btn">
          ⚙ {t("header.settings")}
        </button>

        {onExitDemo && (
          <button onClick={onExitDemo} className="app-header__button btn-ghost">
            {t("demo.exit")}
          </button>
        )}

        {!anonymous && !demoMode && (
          <button onClick={() => session.logout()} className="app-header__button btn-ghost">
            {t("header.logout")}
          </button>
        )}
      </div>
    </header>
  );
}

import React from "react";
import { I18nProvider } from "@/i18n";
import { SettingsProvider } from "@/contexts/SettingsContext";
import { SessionProvider } from "@/contexts/SessionContext";
import { ToastProvider } from "@/contexts/ToastContext";
import { ToastViewport } from "@/components/shell/ToastViewport";
import { PublicConfigProvider } from "@/contexts/PublicConfigContext";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SettingsProvider>
      <I18nProvider>
        <ToastProvider>
          <PublicConfigProvider>
            <SessionProvider>
              {children}
              <ToastViewport />
            </SessionProvider>
          </PublicConfigProvider>
        </ToastProvider>
      </I18nProvider>
    </SettingsProvider>
  );
}

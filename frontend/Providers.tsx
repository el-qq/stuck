import React from "react";
import { I18nProvider } from "@/i18n";
import { SettingsProvider } from "@/contexts/SettingsContext";
import { SessionProvider } from "@/contexts/SessionContext";
import { ToastProvider } from "@/contexts/ToastContext";
import { ToastViewport } from "@/components/ToastViewport";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SettingsProvider>
      <I18nProvider>
        <ToastProvider>
          <SessionProvider>
            {children}
            <ToastViewport />
          </SessionProvider>
        </ToastProvider>
      </I18nProvider>
    </SettingsProvider>
  );
}

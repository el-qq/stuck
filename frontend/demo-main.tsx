import React from "react";
import { createRoot } from "react-dom/client";
import { SettingsProvider } from "@/contexts/SettingsContext";
import { ToastProvider } from "@/contexts/ToastContext";
import { I18nProvider } from "@/i18n";
import { DemoScreen } from "@/components/screens/DemoScreen";
import { ToastViewport } from "@/components/shell/ToastViewport";
import "@/styles/globals.css";

const root = document.getElementById("app-root");
if (!root) throw new Error("Application root element was not found");

/** Static GitHub Pages entry. Deliberately omits the session and public-config
 * providers, so opening the demo cannot bootstrap or contact a backend. */
createRoot(root).render(
  <React.StrictMode>
    <SettingsProvider>
      <I18nProvider>
        <ToastProvider>
          <DemoScreen />
          <ToastViewport />
        </ToastProvider>
      </I18nProvider>
    </SettingsProvider>
  </React.StrictMode>,
);

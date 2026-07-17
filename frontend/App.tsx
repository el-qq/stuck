import React, { useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useI18n } from "@/i18n";
import { LoginScreen } from "@/components/LoginScreen";
import { MainScreen } from "@/components/MainScreen";
import { DemoScreen } from "@/components/DemoScreen";
import { Header } from "@/components/Header";
import { SettingsModal } from "@/components/SettingsModal";

export default function App() {
  const { status } = useSession();
  const { t } = useI18n();
  const [settingsOpen, setSettingsOpen] = useState(false);
  // Iteration 4: demo mode is a separate client-only branch — it never touches
  // the real session/backend, so a real login is unaffected.
  const [demo, setDemo] = useState(false);

  if (demo && status !== "authenticated") {
    return <DemoScreen onExit={() => setDemo(false)} />;
  }

  if (status === "checking") {
    // Iteration 3 (#10): the topbar (with Settings) is visible even while the
    // session status is being resolved.
    return (
      <div className="app-shell">
        <Header anonymous onOpenSettings={() => setSettingsOpen(true)} />
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 10,
            color: "var(--muted)",
            fontSize: 14,
          }}
        >
          <span style={{ display: "inline-block", animation: "spin 1s linear infinite", fontWeight: 700 }}>⟳</span>
          {t("session.checking")}
        </div>
        {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
      </div>
    );
  }

  return status === "authenticated" ? <MainScreen /> : <LoginScreen onEnterDemo={() => setDemo(true)} />;
}

import React, { useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { usePublicConfig } from "@/contexts/PublicConfigContext";
import { useI18n } from "@/i18n";
import { LoginScreen } from "@/components/auth/LoginScreen";
import { TwoFactorForm } from "@/components/auth/TwoFactorForm";
import { DemoScreen } from "@/components/screens/DemoScreen";
import { MainScreen } from "@/components/screens/MainScreen";
import { Header } from "@/components/shell/Header";
import { SettingsModal } from "@/components/shell/SettingsModal";

export default function App() {
  const { status, twoFactorPending, completeTwoFactor, cancelTwoFactor } = useSession();
  const { traceAnimationEnabled } = usePublicConfig();
  const { t } = useI18n();
  const [settingsOpen, setSettingsOpen] = useState(false);
  // Iteration 4: demo mode is a separate client-only branch — it never touches
  // the real session/backend, so a real login is unaffected.
  const [demo, setDemo] = useState(false);

  if (demo && status !== "authenticated") {
    return <DemoScreen onExit={() => setDemo(false)} traceAnimationEnabled={traceAnimationEnabled} />;
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

  // A 2FA challenge (fresh login OR restored from the backend on reload) takes
  // over the screen until it is confirmed or cancelled — the state lives in the
  // session context, so a page refresh keeps showing this form.
  if (status !== "authenticated" && twoFactorPending) {
    return (
      <div className="app-shell">
        <Header anonymous onOpenSettings={() => setSettingsOpen(true)} />
        <div className="login-main" style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
          <TwoFactorForm
            expiresAt={twoFactorPending.expiresAt}
            message={twoFactorPending.message}
            onSuccess={() => completeTwoFactor()}
            onExpired={() => cancelTwoFactor({ notice: true })}
            onReadonlyRequired={() => cancelTwoFactor({ readonlyRequired: true })}
            onCancel={() => cancelTwoFactor()}
          />
        </div>
        {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
      </div>
    );
  }

  return status === "authenticated" ? <MainScreen /> : <LoginScreen onEnterDemo={() => setDemo(true)} />;
}

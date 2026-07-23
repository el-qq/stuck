"use client";

import React, { useState } from "react";
import { usePublicConfig } from "@/contexts/PublicConfigContext";
import { useLoginForm } from "@/hooks/useLoginForm";
import { Header } from "../shell/Header";
import { LoginCard } from "./LoginCard";
import { SettingsModal } from "../shell/SettingsModal";

/** Login-page frame: persistent header/settings plus the isolated login card. */
export function LoginScreen({ onEnterDemo }: { onEnterDemo: () => void }) {
  const { defaultServer } = usePublicConfig();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const form = useLoginForm(defaultServer);

  return (
    <div className="app-shell">
      <Header anonymous onOpenSettings={() => setSettingsOpen(true)} />
      <div
        className="login-main"
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 24,
        }}
      >
        <LoginCard form={form} onEnterDemo={onEnterDemo} />
      </div>
      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

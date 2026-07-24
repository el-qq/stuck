"use client";

import React, { useState } from "react";
import { useI18n } from "@/i18n";
import { DEMO_HYGIENE_REPORT, DEMO_RULES_UPDATED_AT } from "@/lib/demoData";
import { WorkspaceTab } from "@/lib/storage";
import { useDemoRuleSnapshots } from "@/hooks/useDemoRuleSnapshots";
import { useDemoAccessCompare } from "@/hooks/useDemoAccessCompare";
import { useDemoCheck } from "@/hooks/useDemoCheck";
import { HygieneTable } from "../rules/RuleHygieneReportView";
import { Header } from "../shell/Header";
import { SettingsModal } from "../shell/SettingsModal";
import { Workspace } from "./Workspace";

/**
 * Offline implementation of the same rule workspace rendered after login. It
 * feeds the shared `Workspace` local fixtures/adapters instead of the live
 * API-backed hooks `MainScreen` uses. Backend actions stay in their normal
 * places but are disabled by explicit capability flags; this module
 * deliberately imports neither an API client nor session.
 */
interface DemoScreenProps {
  onExit?: () => void;
  /** The live application's public configuration. The standalone static demo
   * uses the safe default and deliberately does not bootstrap this value. */
  traceAnimationEnabled?: boolean;
}

export function DemoScreen({ onExit, traceAnimationEnabled = true }: DemoScreenProps) {
  const { t } = useI18n();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tab, setTab] = useState<WorkspaceTab>("check");
  const [hygieneSection, setHygieneSection] = useState<"all" | HygieneTable>("all");
  const checkState = useDemoCheck();
  const snapshotState = useDemoRuleSnapshots();
  const compareState = useDemoAccessCompare();

  return (
    <div className="app-shell">
      <Header demoMode rulesLoaded rulesUpdatedAt={DEMO_RULES_UPDATED_AT} onOpenSettings={() => setSettingsOpen(true)} exportEnabled onExitDemo={onExit} />

      <div className="demo-banner">
        <span className="demo-banner__label">{t("demo.bannerTitle")}</span>
        <span className="demo-banner__text">{t("demo.bannerText")}</span>
      </div>

      <Workspace
        tab={tab}
        onTabChange={setTab}
        check={checkState}
        hygiene={{
          enabled: true,
          report: DEMO_HYGIENE_REPORT,
          loading: false,
          error: null,
          section: hygieneSection,
          onSectionChange: setHygieneSection,
          backendActionsUnavailable: true,
        }}
        snapshots={{ enabled: true, state: snapshotState, rulesUpdatedAt: DEMO_RULES_UPDATED_AT }}
        compare={{ enabled: true, state: compareState }}
        traceAnimationEnabled={traceAnimationEnabled}
      />

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

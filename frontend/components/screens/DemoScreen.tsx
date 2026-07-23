"use client";

import React, { useRef, useState } from "react";
import { useI18n } from "@/i18n";
import { useMobileResultScroll } from "@/hooks/useMobileResultScroll";
import { DEMO_HYGIENE_REPORT, DEMO_RULES_UPDATED_AT, DEMO_USERS, demoTargetForInput, runDemoTrace } from "@/lib/demoData";
import { TraceResponse } from "@/lib/types";
import { useDemoRuleSnapshots } from "@/hooks/useDemoRuleSnapshots";
import { HygieneTable, hygieneBadgeColor } from "../rules/RuleHygieneReportView";
import { RuleHygieneWorkspace } from "../rules/RuleHygieneWorkspace";
import { SnapshotComparisonWorkspace } from "../rules/SnapshotComparisonWorkspace";
import { diffBadgeColor } from "../rules/SnapshotDiffView";
import { Header } from "../shell/Header";
import { SettingsModal } from "../shell/SettingsModal";
import { WorkspaceTabs } from "../shell/WorkspaceTabs";
import { CheckWorkspace, EmptyTraceResult } from "../trace/CheckWorkspace";
import { DemoTraceForm } from "../trace/DemoTraceForm";
import type { TraceSubmitPayload } from "../trace/TraceForm";
import { TraceResult } from "../trace/TraceResult";

/**
 * Offline implementation of the same rule workspace rendered after login.
 * It passes only local fixtures to shared presentation components. Backend
 * actions stay in their normal places but are disabled by explicit capability
 * flags; this module deliberately imports neither an API client nor session.
 */
export function DemoScreen({ onExit }: { onExit: () => void }) {
  const { t } = useI18n();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tab, setTab] = useState<"check" | "hygiene" | "snapshots">("check");
  const [hygieneSection, setHygieneSection] = useState<"all" | HygieneTable>("all");
  const [result, setResult] = useState<TraceResponse | null>(null);
  const [runKey, setRunKey] = useState(0);
  const resultRef = useRef<HTMLElement>(null);
  const snapshotState = useDemoRuleSnapshots();
  useMobileResultScroll(resultRef, runKey);

  function handleCheck(payload: TraceSubmitPayload) {
    const user = payload.userId ? (DEMO_USERS.find((candidate) => candidate.id === payload.userId) ?? null) : null;
    setResult(runDemoTrace(demoTargetForInput(payload.url), user, t, payload.sourceIp));
    setRunKey((key) => key + 1);
  }

  const workspaceTabs = (
    <WorkspaceTabs ariaLabel={t("tabs.aria")}>
      <button
        role="tab"
        id="tab-check"
        aria-selected={tab === "check"}
        aria-controls="tabpanel-check"
        className="workspace-tabs__tab"
        onClick={() => setTab("check")}
      >
        {t("tabs.check")}
      </button>
      <button
        role="tab"
        id="tab-hygiene"
        aria-selected={tab === "hygiene"}
        aria-controls="tabpanel-hygiene"
        className="workspace-tabs__tab"
        onClick={() => setTab("hygiene")}
      >
        {t("hygiene.title")}
        <span className="workspace-tabs__badge" style={{ background: hygieneBadgeColor(DEMO_HYGIENE_REPORT.summary) }}>
          {DEMO_HYGIENE_REPORT.summary.total}
        </span>
      </button>
      <button
        role="tab"
        id="tab-snapshots"
        aria-selected={tab === "snapshots"}
        aria-controls="tabpanel-snapshots"
        className="workspace-tabs__tab"
        onClick={() => setTab("snapshots")}
      >
        {t("snapshots.title")}
        {snapshotState.diffChangeCount > 0 && (
          <span className="workspace-tabs__badge" style={{ background: diffBadgeColor(snapshotState.diff!.summary) }}>
            {snapshotState.diffChangeCount}
          </span>
        )}
      </button>
    </WorkspaceTabs>
  );

  return (
    <div className="app-shell">
      <Header demoMode rulesLoaded rulesUpdatedAt={DEMO_RULES_UPDATED_AT} onOpenSettings={() => setSettingsOpen(true)} exportEnabled onExitDemo={onExit} />

      <div className="demo-banner">
        <span className="demo-banner__label">{t("demo.bannerTitle")}</span>
        <span className="demo-banner__text">{t("demo.bannerText")}</span>
      </div>

      {workspaceTabs}

      {tab === "hygiene" && (
        <RuleHygieneWorkspace
          report={DEMO_HYGIENE_REPORT}
          loading={false}
          error={null}
          section={hygieneSection}
          onSectionChange={setHygieneSection}
          backendActionsUnavailable
        />
      )}

      {tab === "snapshots" && <SnapshotComparisonWorkspace state={snapshotState} rulesUpdatedAt={DEMO_RULES_UPDATED_AT} />}

      <div role="tabpanel" id="tabpanel-check" aria-labelledby="tab-check" style={{ display: tab === "check" ? "contents" : "none" }}>
        <CheckWorkspace
          resultRef={resultRef}
          controls={<DemoTraceForm submitting={false} onSubmit={handleCheck} />}
          result={result ? <TraceResult key={runKey} result={result} /> : <EmptyTraceResult />}
        />
      </div>

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

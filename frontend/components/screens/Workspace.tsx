"use client";

import React from "react";
import { useI18n } from "@/i18n";
import type { WorkspaceTab } from "@/lib/storage";
import { RuleHygieneReport } from "@/lib/types";
import type { AccessCompareState } from "../compare/accessCompareState";
import { AccessCompareWorkspace } from "../compare/AccessCompareWorkspace";
import { HygieneTable, hygieneBadgeColor } from "../rules/RuleHygieneReportView";
import { RuleHygieneWorkspace } from "../rules/RuleHygieneWorkspace";
import { diffBadgeColor } from "../rules/SnapshotDiffView";
import { SnapshotComparisonWorkspace } from "../rules/SnapshotComparisonWorkspace";
import type { SnapshotWorkspaceState } from "../rules/snapshotWorkspaceState";
import { WorkspaceTabs } from "../shell/WorkspaceTabs";
import type { CheckState } from "../trace/checkState";
import { TraceCheckWorkspace } from "../trace/TraceCheckWorkspace";

interface HygieneSection {
  enabled: boolean;
  report: RuleHygieneReport | null;
  loading: boolean;
  error: string | null;
  section: "all" | HygieneTable;
  onSectionChange: (section: "all" | HygieneTable) => void;
  onRecheck?: () => void;
  /** Demos retain the control's layout but must never invoke backend refresh. */
  backendActionsUnavailable?: boolean;
}

interface SnapshotsSection {
  enabled: boolean;
  state: SnapshotWorkspaceState;
  rulesUpdatedAt: string | null;
}

interface CompareSection {
  enabled: boolean;
  state: AccessCompareState;
}

interface Props {
  tab: WorkspaceTab;
  onTabChange: (tab: WorkspaceTab) => void;
  check: CheckState;
  hygiene: HygieneSection;
  snapshots: SnapshotsSection;
  compare: CompareSection;
  /** NGFW HTTPS port and identity for deep links into the console; both
   * absent in the demo (its results never point at a real appliance). */
  server?: string;
  port?: number;
  traceAnimationEnabled?: boolean;
}

/**
 * Shared top-level workspace for both the live and offline-demo screens: the
 * tab bar and all four tab panels. Live hides an optional tab behind its
 * config flag; the demo passes every section `enabled: true` so it always
 * illustrates the full product. The only thing that differs between callers
 * is which state adapter (live API hook vs. local demo adapter) feeds each
 * section — this component itself never imports an API client or session.
 */
export function Workspace({ tab, onTabChange, check, hygiene, snapshots, compare, server, port, traceAnimationEnabled }: Props) {
  const { t } = useI18n();

  const showTabs = hygiene.enabled || snapshots.enabled || compare.enabled;
  // A restored (or previously selected) tab may not be available now — the
  // feature flag is off, or the role lost trace access. Fall back to "check"
  // for rendering while keeping the stored intent, so it re-appears if the
  // tab becomes available again.
  const tabAvailable: Record<WorkspaceTab, boolean> = { check: true, hygiene: hygiene.enabled, snapshots: snapshots.enabled, compare: compare.enabled };
  const activeTab: WorkspaceTab = tabAvailable[tab] ? tab : "check";
  const compareDivergentCount = compare.state.result ? compare.state.result.stages.filter((stage) => stage.classification === "divergent").length : 0;

  return (
    <>
      {showTabs && (
        <WorkspaceTabs ariaLabel={t("tabs.aria")}>
          <button
            role="tab"
            id="tab-check"
            aria-selected={activeTab === "check"}
            aria-controls="tabpanel-check"
            className="workspace-tabs__tab"
            onClick={() => onTabChange("check")}
          >
            {t("tabs.check")}
          </button>
          {compare.enabled && (
            <button
              role="tab"
              id="tab-compare"
              aria-selected={activeTab === "compare"}
              aria-controls="tabpanel-compare"
              className="workspace-tabs__tab"
              onClick={() => onTabChange("compare")}
            >
              {t("compare.title")}
              {compareDivergentCount > 0 && (
                <span className="workspace-tabs__badge" style={{ background: "var(--bad)" }}>
                  {compareDivergentCount}
                </span>
              )}
            </button>
          )}
          {/* Divider between the "traffic" tabs (check, compare) and the "rules"
              tabs (hygiene, snapshots) — only meaningful when a rules tab exists. */}
          {(hygiene.enabled || snapshots.enabled) && <span className="workspace-tabs__divider" aria-hidden="true" />}
          {hygiene.enabled && (
            <button
              role="tab"
              id="tab-hygiene"
              aria-selected={activeTab === "hygiene"}
              aria-controls="tabpanel-hygiene"
              className="workspace-tabs__tab"
              onClick={() => onTabChange("hygiene")}
            >
              {t("hygiene.title")}
              {hygiene.report !== null && hygiene.report.summary.total > 0 && (
                <span className="workspace-tabs__badge" style={{ background: hygieneBadgeColor(hygiene.report.summary) }}>
                  {hygiene.report.summary.total}
                </span>
              )}
            </button>
          )}
          {snapshots.enabled && (
            <button
              role="tab"
              id="tab-snapshots"
              aria-selected={activeTab === "snapshots"}
              aria-controls="tabpanel-snapshots"
              className="workspace-tabs__tab"
              onClick={() => onTabChange("snapshots")}
            >
              {t("snapshots.title")}
              {snapshots.state.diffChangeCount > 0 && (
                <span className="workspace-tabs__badge" style={{ background: diffBadgeColor(snapshots.state.diff!.summary) }}>
                  {snapshots.state.diffChangeCount}
                </span>
              )}
            </button>
          )}
        </WorkspaceTabs>
      )}

      {/* Hygiene and snapshots are conditionally rendered (not display:none) —
          unlike the check tab, neither has animation state to preserve across
          a remount, and keeping both mounted at once duplicates group labels
          they share (e.g. "Firewall · Forward"), breaking strict-mode text
          queries. Only the active one of the two is ever in the DOM. */}
      {hygiene.enabled && activeTab === "hygiene" && (
        <RuleHygieneWorkspace
          report={hygiene.report}
          loading={hygiene.loading}
          error={hygiene.error}
          section={hygiene.section}
          onSectionChange={hygiene.onSectionChange}
          onRecheck={hygiene.onRecheck}
          backendActionsUnavailable={hygiene.backendActionsUnavailable}
          port={port}
        />
      )}

      {snapshots.enabled && activeTab === "snapshots" && (
        <SnapshotComparisonWorkspace state={snapshots.state} rulesUpdatedAt={snapshots.rulesUpdatedAt} port={port} />
      )}

      {compare.enabled && activeTab === "compare" && <AccessCompareWorkspace state={compare.state} server={server} port={port} />}

      {/* The check tabpanel stays MOUNTED and toggles via display — unmounting
          would reset useStageReveal and replay the trace animation on every
          return to the tab. */}
      <div
        role={showTabs ? "tabpanel" : undefined}
        id="tabpanel-check"
        aria-labelledby={showTabs ? "tab-check" : undefined}
        style={{ display: activeTab === "check" ? "contents" : "none" }}
      >
        <TraceCheckWorkspace state={check} traceAnimationEnabled={traceAnimationEnabled} ngfwServer={server} ngfwPort={port} />
      </div>
    </>
  );
}

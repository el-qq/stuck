"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { DiffSummary, SnapshotDiffResponse } from "@/lib/types";
import { SnapshotDiffGroups } from "./SnapshotDiffGroups";
import { DIFF_KIND_COLOR, groupDiffTables } from "./snapshotDiffPresentation";

export { DIFF_KIND_COLOR } from "./snapshotDiffPresentation";

/** Tab badge color — removed/changed rules are the most consequential change,
 * followed by additions, moves and module-state toggles. */
export function diffBadgeColor(summary: Pick<DiffSummary, "added" | "removed" | "changed" | "moved" | "states_changed">): string {
  if (summary.removed > 0 || summary.changed > 0) return "var(--warn)";
  if (summary.added > 0 || summary.moved > 0 || summary.states_changed > 0) return "var(--info)";
  return "var(--ok)";
}

export function DiffSummaryCounters({ summary }: { summary: DiffSummary }) {
  const { t } = useI18n();
  return (
    <div className="snapshot-diff__counters">
      <Counter color={DIFF_KIND_COLOR.added} label={t("snapshots.countAdded", { count: summary.added })} />
      <Counter color={DIFF_KIND_COLOR.removed} label={t("snapshots.countRemoved", { count: summary.removed })} />
      <Counter color={DIFF_KIND_COLOR.changed} label={t("snapshots.countChanged", { count: summary.changed })} />
      <Counter color={DIFF_KIND_COLOR.moved} label={t("snapshots.countMoved", { count: summary.moved })} />
    </div>
  );
}

function Counter({ color, label }: { color: string; label: string }) {
  return (
    <span className="snapshot-diff__counter">
      <span aria-hidden="true" className="snapshot-diff__counter-dot" style={{ background: color }} />
      {label}
    </span>
  );
}

interface Props {
  diff: SnapshotDiffResponse;
  /** NGFW HTTPS port for deep links; absent in the offline demo. */
  port?: number;
  /** Constrain the groups list; unset lets the page own scrolling. */
  listMaxHeight?: string;
}

/** Presentational snapshot diff, shared by live and demo workspaces. It only
 * renders React text nodes — server values never become HTML. */
export function SnapshotDiffView({ diff, port, listMaxHeight }: Props) {
  const { t } = useI18n();
  const groups = groupDiffTables(diff.tables);
  const noChanges = groups.length === 0 && diff.states.length === 0;

  return (
    <section className="snapshot-diff">
      {diff.comparison_mode === "anonymized" && (
        <div role="status" className="snapshot-diff__banner snapshot-diff__banner--info">
          {t("snapshots.anonymizedBanner")}
        </div>
      )}
      {(diff.a.foreign_server === true || diff.b.foreign_server === true) && (
        <div role="status" className="snapshot-diff__banner snapshot-diff__banner--warning">
          {t("snapshots.foreignServerBanner")}
        </div>
      )}

      <DiffSummaryCounters summary={diff.summary} />

      {noChanges ? (
        <div className="snapshot-diff__clean">✓ {t("snapshots.diffClean")}</div>
      ) : (
        <SnapshotDiffGroups
          groups={groups}
          states={diff.states}
          before={diff.a}
          after={diff.b}
          server={diff.binding.server}
          port={port}
          listMaxHeight={listMaxHeight}
        />
      )}
    </section>
  );
}

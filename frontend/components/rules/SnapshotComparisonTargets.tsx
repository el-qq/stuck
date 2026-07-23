"use client";

import React, { DragEvent } from "react";
import { useI18n } from "@/i18n";
import { SnapshotOrCurrentId } from "@/lib/types";
import { formatSnapshotDate, importedSnapshotFileName, SnapshotChoice, SnapshotComparisonSide, snapshotCountsTotal } from "./snapshotComparison";

interface Props {
  before: SnapshotChoice;
  after: SnapshotChoice;
  activeSide: SnapshotComparisonSide;
  onActivate: (side: SnapshotComparisonSide) => void;
  onDropChoice: (side: SnapshotComparisonSide, id: SnapshotOrCurrentId) => void;
  onSwap: () => void;
}

/** The two target cards make the direction of every diff unambiguous. They
 * are ordinary buttons first; desktop drag-and-drop is only an enhancement. */
export function SnapshotComparisonTargets({ before, after, activeSide, onActivate, onDropChoice, onSwap }: Props) {
  const { t } = useI18n();
  return (
    <div className="snapshot-comparison__targets" aria-label={t("snapshots.compareTitle")}>
      <SideTarget side="before" choice={before} active={activeSide === "before"} onActivate={onActivate} onDropChoice={onDropChoice} />
      <button type="button" className="snapshot-comparison__swap" onClick={onSwap} aria-label={t("snapshots.swapSides")} title={t("snapshots.swapSides")}>
        ⇄
      </button>
      <SideTarget side="after" choice={after} active={activeSide === "after"} onActivate={onActivate} onDropChoice={onDropChoice} />
    </div>
  );
}

function SideTarget({
  side,
  choice,
  active,
  onActivate,
  onDropChoice,
}: {
  side: SnapshotComparisonSide;
  choice: SnapshotChoice;
  active: boolean;
  onActivate: (side: SnapshotComparisonSide) => void;
  onDropChoice: (side: SnapshotComparisonSide, id: SnapshotOrCurrentId) => void;
}) {
  const { t, locale } = useI18n();
  const fileName = importedSnapshotFileName(choice);
  const detailsLabel = fileName ?? choice.comment;
  const total = snapshotCountsTotal(choice.counts);

  function handleDrop(event: DragEvent<HTMLButtonElement>) {
    event.preventDefault();
    const id = event.dataTransfer.getData("text/plain");
    if (id) onDropChoice(side, id);
  }

  return (
    <button
      type="button"
      className="snapshot-comparison__target"
      data-side={side}
      data-active={active}
      onClick={() => onActivate(side)}
      onDragOver={(event) => event.preventDefault()}
      onDrop={handleDrop}
      aria-pressed={active}
    >
      <span className="snapshot-comparison__target-label">{side === "before" ? t("snapshots.before") : t("snapshots.after")}</span>
      <span className="snapshot-comparison__target-title">
        {choice.source === "current" ? t("snapshots.current") : formatSnapshotDate(choice.created_at, locale)}
      </span>
      {choice.rules_updated_at && <span className="snapshot-comparison__target-meta">{formatSnapshotDate(choice.rules_updated_at, locale)}</span>}
      {total > 0 && <span className="snapshot-comparison__target-meta">{t("snapshots.rowCounts", { count: total })}</span>}
      {choice.source === "imported" && <span className="snapshot-comparison__target-meta">{t("snapshots.sourceImported")}</span>}
      {detailsLabel && (
        <span className="snapshot-comparison__target-meta snapshot-comparison__target-file" title={detailsLabel}>
          {detailsLabel}
        </span>
      )}
    </button>
  );
}

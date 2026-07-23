"use client";

import React, { DragEvent, useMemo, useState } from "react";
import { useI18n } from "@/i18n";
import { SnapshotDescriptor, SnapshotDiffResponse, SnapshotOrCurrentId } from "@/lib/types";
import { SnapshotDiffView } from "./SnapshotDiffView";

/** A demo-only selector item.  `current` behaves like a snapshot in the UI,
 * but it is not persisted in the saved-snapshot list. */
type DemoSnapshotChoice = Omit<SnapshotDescriptor, "source"> & {
  source: SnapshotDescriptor["source"] | "current";
};

interface Props {
  current: DemoSnapshotChoice;
  snapshots: SnapshotDescriptor[];
  limit: number;
  exampleDiff: SnapshotDiffResponse;
}

type Side = "before" | "after";

/**
 * Offline prototype of the snapshot picker proposed for the live workspace.
 *
 * The two target cards make the comparison direction explicit.  Drag-and-drop
 * enhances desktop interaction, while target-card + ordinary click remains the
 * complete keyboard and touch path.  The detailed result intentionally reuses
 * one static demo fixture: the component demonstrates selection and layout,
 * never claims to calculate an NGFW diff locally.
 */
export function DemoSnapshotComparison({ current, snapshots, limit, exampleDiff }: Props) {
  const { t, locale } = useI18n();
  const choices = [current, ...snapshots];
  const [beforeId, setBeforeId] = useState<SnapshotOrCurrentId>(current.id);
  const [afterId, setAfterId] = useState<SnapshotOrCurrentId>(current.id);
  const [activeSide, setActiveSide] = useState<Side>("before");

  const before = findChoice(choices, beforeId, current);
  const after = findChoice(choices, afterId, current);
  const hasComparison = before.id !== after.id;

  const previewDiff = useMemo<SnapshotDiffResponse | null>(() => {
    if (!hasComparison) return null;
    return {
      ...exampleDiff,
      a: asDiffSide(before),
      b: asDiffSide(after),
      comparison_mode: before.source === "imported" || after.source === "imported" ? "anonymized" : "full",
    };
  }, [after, before, exampleDiff, hasComparison]);

  function assign(side: Side, id: SnapshotOrCurrentId) {
    if (side === "before") {
      setBeforeId(id);
      setActiveSide("after");
    } else {
      setAfterId(id);
      setActiveSide("before");
    }
  }

  function handleDrop(event: DragEvent<HTMLElement>, side: Side) {
    event.preventDefault();
    const id = event.dataTransfer.getData("text/plain");
    if (choices.some((choice) => choice.id === id)) assign(side, id);
  }

  function handleDragStart(event: DragEvent<HTMLButtonElement>, id: string) {
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", id);
  }

  function swapSides() {
    setBeforeId(after.id);
    setAfterId(before.id);
    setActiveSide("before");
  }

  return (
    <main role="tabpanel" id="tabpanel-snapshots" aria-labelledby="tab-snapshots" className="hygiene-workspace">
      <aside className="hygiene-workspace__controls">
        <div className="check-panel">
          <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("snapshots.title")}</div>
          <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 14 }}>{t("snapshots.subtitle")}</div>

          <div className="demo-snapshot-picker__hint">{t("snapshots.selectionHint")}</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "16px 0 8px" }}>
            <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("snapshots.listTitle")}</span>
            <span className="hygiene-nav__count">{t("snapshots.limitCounter", { count: snapshots.length, limit })}</span>
          </div>

          <div className="demo-snapshot-picker__list">
            {choices.map((choice) => {
              const isBefore = choice.id === before.id;
              const isAfter = choice.id === after.id;
              return (
                <button
                  key={choice.id}
                  type="button"
                  draggable
                  className="demo-snapshot-picker__item"
                  data-before={isBefore}
                  data-after={isAfter}
                  onClick={() => assign(activeSide, choice.id)}
                  onDragStart={(event) => handleDragStart(event, choice.id)}
                  aria-label={snapshotLabel(choice, locale, t)}
                >
                  <div className="demo-snapshot-picker__item-head">
                    <span className="demo-snapshot-picker__item-date">
                      {choice.source === "current" ? t("snapshots.current") : formatDate(choice.created_at, locale)}
                    </span>
                    <SelectionBadges before={isBefore} after={isAfter} />
                  </div>
                  <div className="demo-snapshot-picker__badges">
                    {choice.source !== "current" && <SourceBadge source={choice.source} t={t} />}
                    {choice.foreign_server && (
                      <span className="demo-snapshot-picker__badge demo-snapshot-picker__badge--foreign">{t("snapshots.foreignBadge")}</span>
                    )}
                  </div>
                  {choice.source !== "current" && choice.comment && <div className="demo-snapshot-picker__comment">{choice.comment}</div>}
                  {choice.source === "imported" && choice.file_name && (
                    <div className="demo-snapshot-picker__comment" title={choice.file_name}>
                      {choice.file_name}
                    </div>
                  )}
                  <div className="demo-snapshot-picker__count">{t("snapshots.rowCounts", { count: countsTotal(choice.counts) })}</div>
                </button>
              );
            })}
          </div>
        </div>
      </aside>

      <section className="hygiene-workspace__result">
        <div className="demo-comparison__targets" aria-label={t("snapshots.compareTitle")}>
          <SideTarget side="before" choice={before} active={activeSide === "before"} onActivate={() => setActiveSide("before")} onDrop={handleDrop} />
          <button type="button" className="demo-comparison__swap" onClick={swapSides} aria-label={t("snapshots.swapSides")} title={t("snapshots.swapSides")}>
            ⇄
          </button>
          <SideTarget side="after" choice={after} active={activeSide === "after"} onActivate={() => setActiveSide("after")} onDrop={handleDrop} />
        </div>

        {previewDiff ? (
          <div className="demo-comparison__result">
            <SnapshotDiffView diff={previewDiff} />
          </div>
        ) : (
          <div className="demo-comparison__empty">
            <span aria-hidden="true">⇄</span>
            <div>{t("snapshots.selectionEmpty")}</div>
          </div>
        )}
      </section>
    </main>
  );
}

function SideTarget({
  side,
  choice,
  active,
  onActivate,
  onDrop,
}: {
  side: Side;
  choice: DemoSnapshotChoice;
  active: boolean;
  onActivate: () => void;
  onDrop: (event: DragEvent<HTMLElement>, side: Side) => void;
}) {
  const { t, locale } = useI18n();
  const label = side === "before" ? t("snapshots.before") : t("snapshots.after");
  const sourceName = choice.source === "imported" ? (choice.file_name ?? choice.comment) : choice.comment;
  return (
    <button
      type="button"
      className="demo-comparison__target"
      data-side={side}
      data-active={active}
      onClick={onActivate}
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => onDrop(event, side)}
      aria-pressed={active}
    >
      <span className="demo-comparison__target-label">{label}</span>
      <span className="demo-comparison__target-title">{choice.source === "current" ? t("snapshots.current") : formatDate(choice.created_at, locale)}</span>
      <span className="demo-comparison__target-meta">{t("snapshots.rowCounts", { count: countsTotal(choice.counts) })}</span>
      {choice.source === "imported" && <span className="demo-comparison__target-meta">{t("snapshots.sourceImported")}</span>}
      {sourceName && (
        <span className="demo-comparison__target-meta demo-comparison__target-file" title={sourceName}>
          {sourceName}
        </span>
      )}
    </button>
  );
}

function SelectionBadges({ before, after }: { before: boolean; after: boolean }) {
  const { t } = useI18n();
  if (!before && !after) return null;
  return (
    <span className="demo-snapshot-picker__selection">
      {before && <span data-side="before">{t("snapshots.before")}</span>}
      {after && <span data-side="after">{t("snapshots.after")}</span>}
    </span>
  );
}

function SourceBadge({ source, t }: { source: SnapshotDescriptor["source"]; t: ReturnType<typeof useI18n>["t"] }) {
  const imported = source === "imported";
  return (
    <span className="demo-snapshot-picker__badge" data-imported={imported}>
      {imported ? t("snapshots.sourceImported") : t("snapshots.sourceManual")}
    </span>
  );
}

function findChoice(choices: DemoSnapshotChoice[], id: SnapshotOrCurrentId, fallback: DemoSnapshotChoice): DemoSnapshotChoice {
  return choices.find((choice) => choice.id === id) ?? fallback;
}

function asDiffSide(choice: DemoSnapshotChoice): SnapshotDiffResponse["a"] {
  return {
    id: choice.id,
    created_at: choice.created_at,
    rules_updated_at: choice.rules_updated_at,
    comment: choice.comment,
    source: choice.source,
    ...(choice.foreign_server ? { foreign_server: true } : {}),
    ...(choice.source === "imported" && choice.file_name ? { file_name: choice.file_name } : {}),
  };
}

function countsTotal(counts: Record<string, number>): number {
  return Object.values(counts).reduce((sum, value) => sum + (Number.isFinite(value) ? value : 0), 0);
}

function formatDate(iso: string, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "medium" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

function snapshotLabel(choice: DemoSnapshotChoice, locale: string, t: ReturnType<typeof useI18n>["t"]): string {
  if (choice.source === "current") return t("snapshots.current");
  const name = choice.comment ? `${formatDate(choice.created_at, locale)} — ${choice.comment}` : formatDate(choice.created_at, locale);
  return `${name}, ${t("snapshots.rowCounts", { count: countsTotal(choice.counts) })}`;
}

"use client";

import React from "react";
import { useI18n } from "@/i18n";
import type { DiffEntry, DiffKind, DiffSide, DiffTable } from "@/lib/types";
import { DIFF_KIND_COLOR, formatDiffValue, ruleSectionLink } from "./snapshotDiffPresentation";

interface Props {
  entry: DiffEntry;
  table: DiffTable;
  before: DiffSide;
  after: DiffSide;
  server: string;
  port?: number;
}

export function SnapshotDiffEntry({ entry, table, before, after, server, port }: Props) {
  const { t } = useI18n();
  const link = ruleSectionLink({ entry, table, before, after, server, port });

  return (
    <article className="snapshot-diff-entry" data-kind={entry.kind}>
      <div className="snapshot-diff-entry__header">
        <span className="snapshot-diff-entry__kind" style={{ color: DIFF_KIND_COLOR[entry.kind] }}>
          {kindLabel(t, entry.kind)}
        </span>
        <span className="snapshot-diff-entry__meta">
          {positionLabel(t, entry)} · id={entry.id}
        </span>
        {link && (
          <a href={link} target="_blank" rel="noopener noreferrer" className="snapshot-diff-entry__link">
            {t("common.openNgfwSection")} ↗
          </a>
        )}
      </div>

      {entry.name && (
        <div className="snapshot-diff-entry__name" title={entry.name}>
          «{entry.name}»
        </div>
      )}
      {entry.changed_fields && entry.changed_fields.length > 0 && <ChangedFields fields={entry.changed_fields} />}
    </article>
  );
}

function ChangedFields({ fields }: { fields: NonNullable<DiffEntry["changed_fields"]> }) {
  const { t } = useI18n();
  return (
    <div className="snapshot-diff-entry__fields">
      <div className="snapshot-diff-entry__field-header" aria-hidden="true">
        <span />
        <span>{t("snapshots.before")}</span>
        <span>{t("snapshots.after")}</span>
      </div>
      {fields.map((field) => (
        <div className="snapshot-diff-entry__field" key={field.field}>
          <span className="snapshot-diff-entry__field-name">{field.field}</span>
          <Value side="before" label={t("snapshots.before")} value={field.from} />
          <Value side="after" label={t("snapshots.after")} value={field.to} />
        </div>
      ))}
    </div>
  );
}

function Value({ side, label, value }: { side: "before" | "after"; label: string; value: unknown }) {
  return (
    <span className="snapshot-diff-entry__field-value" data-side={side}>
      <span className="snapshot-diff-entry__field-mobile-label">{label}</span>
      <span className="mono">{formatDiffValue(value)}</span>
    </span>
  );
}

type TFn = ReturnType<typeof useI18n>["t"];

function kindLabel(t: TFn, kind: DiffKind): string {
  switch (kind) {
    case "added":
      return t("snapshots.kindAdded");
    case "removed":
      return t("snapshots.kindRemoved");
    case "changed":
      return t("snapshots.kindChanged");
    case "moved":
      return t("snapshots.kindMoved");
  }
}

function positionLabel(t: TFn, entry: DiffEntry): string {
  if (entry.kind === "added") return t("snapshots.positionAdded", { position: entry.position_b ?? "?" });
  if (entry.kind === "removed") return t("snapshots.positionRemoved", { position: entry.position_a ?? "?" });
  return t("snapshots.positionBoth", { a: entry.position_a ?? "?", b: entry.position_b ?? "?" });
}

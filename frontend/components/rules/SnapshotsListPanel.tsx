"use client";

import React, { DragEvent, useRef } from "react";
import { useI18n } from "@/i18n";
import { SnapshotDescriptor, SnapshotOrCurrentId } from "@/lib/types";
import { formatSnapshotDate, importedSnapshotFileName, SnapshotChoice, SnapshotComparisonSide, snapshotCountsTotal } from "./snapshotComparison";

interface Props {
  /** Includes the pinned `current` state as its first item. */
  choices: SnapshotChoice[];
  limit: number;
  loading: boolean;
  error: string | null;

  comment: string;
  onCommentChange: (value: string) => void;
  creating: boolean;
  onCreate: () => void;

  importing: boolean;
  importError: string | null;
  onImportFile: (file: File) => void;

  deletingId: string | null;
  onDeleteRequest: (snapshot: SnapshotDescriptor) => void;

  beforeId: SnapshotOrCurrentId;
  afterId: SnapshotOrCurrentId;
  activeSide: SnapshotComparisonSide;
  onAssign: (side: SnapshotComparisonSide, id: SnapshotOrCurrentId) => void;
  /** Keep backend-backed actions visible but inert in the offline demo. */
  backendActionsUnavailable?: boolean;
}

/**
 * The left-side snapshot library. A click always assigns the item to the
 * explicitly active `Before`/`After` target, and desktop drag-and-drop maps
 * to the same callback. This keeps the touch and keyboard paths equivalent.
 */
export function SnapshotsListPanel({
  choices,
  limit,
  loading,
  error,
  comment,
  onCommentChange,
  creating,
  onCreate,
  importing,
  importError,
  onImportFile,
  deletingId,
  onDeleteRequest,
  beforeId,
  afterId,
  activeSide,
  onAssign,
  backendActionsUnavailable = false,
}: Props) {
  const { t } = useI18n();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const snapshots = choices.filter((choice): choice is SnapshotDescriptor => choice.source !== "current");

  function handleDragStart(event: DragEvent<HTMLButtonElement>, id: SnapshotOrCurrentId) {
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", id);
  }

  return (
    <div className="check-panel">
      <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("snapshots.title")}</div>
      <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 14 }}>{t("snapshots.subtitle")}</div>

      <div className="snapshot-picker__hint">{t("snapshots.selectionHint")}</div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "16px 0 8px" }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("snapshots.listTitle")}</span>
        <span className="hygiene-nav__count">{t("snapshots.limitCounter", { count: snapshots.length, limit })}</span>
      </div>

      <div className="snapshot-picker__list" aria-label={t("snapshots.listTitle")}>
        {choices.map((choice) => (
          <SnapshotChoiceRow
            key={choice.id}
            choice={choice}
            isBefore={choice.id === beforeId}
            isAfter={choice.id === afterId}
            activeSide={activeSide}
            onAssign={onAssign}
            onDragStart={handleDragStart}
            deleting={deletingId === choice.id}
            onDeleteRequest={onDeleteRequest}
            backendActionsUnavailable={backendActionsUnavailable}
          />
        ))}
      </div>

      <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />

      <input
        className="form-control"
        value={comment}
        onChange={(event) => onCommentChange(event.target.value)}
        disabled={backendActionsUnavailable}
        placeholder={t("snapshots.commentPlaceholder")}
        maxLength={200}
        style={{ ...inputStyle, marginBottom: 8 }}
      />
      <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
        <button
          type="button"
          className="btn-primary"
          onClick={backendActionsUnavailable ? undefined : onCreate}
          disabled={backendActionsUnavailable || creating || loading}
          title={backendActionsUnavailable ? t("demo.backendActionUnavailable") : undefined}
          data-demo-unavailable={backendActionsUnavailable || undefined}
          style={actionButtonStyle}
        >
          {creating ? t("snapshots.creating") : t("snapshots.create")}
        </button>
        <button
          type="button"
          className="btn-outline"
          onClick={backendActionsUnavailable ? undefined : () => fileInputRef.current?.click()}
          disabled={backendActionsUnavailable || importing}
          title={backendActionsUnavailable ? t("demo.backendActionUnavailable") : undefined}
          data-demo-unavailable={backendActionsUnavailable || undefined}
          style={actionButtonStyle}
        >
          {importing ? t("snapshots.importing") : t("snapshots.import")}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept="application/json,.json"
          style={{ display: "none" }}
          onClick={(event) => {
            event.currentTarget.value = "";
          }}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) onImportFile(file);
          }}
        />
      </div>
      {backendActionsUnavailable && <p className="demo-unavailable-hint">{t("demo.backendActionsUnavailable")}</p>}
      {importError && (
        <div role="alert" className="snapshot-comparison__error">
          {importError}
        </div>
      )}

      {loading && snapshots.length === 0 ? (
        <div style={{ fontSize: 13, color: "var(--muted)", marginTop: 12 }}>{t("common.loading")}</div>
      ) : error ? (
        <div role="alert" className="snapshot-comparison__error" style={{ marginTop: 12 }}>
          {error}
        </div>
      ) : snapshots.length === 0 ? (
        <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginTop: 12 }}>{t("snapshots.empty")}</div>
      ) : null}
    </div>
  );
}

function SnapshotChoiceRow({
  choice,
  isBefore,
  isAfter,
  activeSide,
  onAssign,
  onDragStart,
  deleting,
  onDeleteRequest,
  backendActionsUnavailable,
}: {
  choice: SnapshotChoice;
  isBefore: boolean;
  isAfter: boolean;
  activeSide: SnapshotComparisonSide;
  onAssign: (side: SnapshotComparisonSide, id: SnapshotOrCurrentId) => void;
  onDragStart: (event: DragEvent<HTMLButtonElement>, id: SnapshotOrCurrentId) => void;
  deleting: boolean;
  onDeleteRequest: (snapshot: SnapshotDescriptor) => void;
  backendActionsUnavailable: boolean;
}) {
  const { t, locale } = useI18n();
  const total = snapshotCountsTotal(choice.counts);
  const fileName = importedSnapshotFileName(choice);
  const itemLabel = choice.source === "current" ? t("snapshots.current") : formatSnapshotDate(choice.created_at, locale);
  // A date alone makes adjacent snapshots indistinguishable to screen-reader
  // users. Keep the visible compact row, but expose its useful identity too.
  const accessibleLabel = [itemLabel, choice.comment, fileName].filter(Boolean).join(", ");

  return (
    <div className="snapshot-picker__row" data-before={isBefore} data-after={isAfter}>
      <button
        type="button"
        draggable
        className="snapshot-picker__item"
        onClick={() => onAssign(activeSide, choice.id)}
        onDragStart={(event) => onDragStart(event, choice.id)}
        aria-label={accessibleLabel}
      >
        <span className="snapshot-picker__item-head">
          <span className="snapshot-picker__item-date">{itemLabel}</span>
          <SelectionBadges before={isBefore} after={isAfter} />
        </span>
        {choice.source !== "current" && (
          <span className="snapshot-picker__badges">
            <SourceBadge source={choice.source} />
            {choice.foreign_server && <span className="snapshot-picker__badge snapshot-picker__badge--foreign">{t("snapshots.foreignBadge")}</span>}
          </span>
        )}
        {choice.source !== "current" && choice.comment && <span className="snapshot-picker__comment">{choice.comment}</span>}
        {fileName && (
          <span className="snapshot-picker__comment" title={fileName}>
            {fileName}
          </span>
        )}
        {choice.rules_updated_at && <span className="snapshot-picker__count">{formatSnapshotDate(choice.rules_updated_at, locale)}</span>}
        {total > 0 && <span className="snapshot-picker__count">{t("snapshots.rowCounts", { count: total })}</span>}
      </button>
      {choice.source !== "current" && (
        <button
          type="button"
          className="btn-ghost snapshot-picker__delete"
          aria-label={t("snapshots.delete")}
          onClick={backendActionsUnavailable ? undefined : () => onDeleteRequest(choice)}
          disabled={backendActionsUnavailable || deleting}
          title={backendActionsUnavailable ? t("demo.backendActionUnavailable") : t("snapshots.delete")}
          data-demo-unavailable={backendActionsUnavailable || undefined}
        >
          {deleting ? "…" : "✕"}
        </button>
      )}
    </div>
  );
}

function SelectionBadges({ before, after }: { before: boolean; after: boolean }) {
  const { t } = useI18n();
  if (!before && !after) return null;
  return (
    <span className="snapshot-picker__selection">
      {before && <span data-side="before">{t("snapshots.before")}</span>}
      {after && <span data-side="after">{t("snapshots.after")}</span>}
    </span>
  );
}

function SourceBadge({ source }: { source: SnapshotDescriptor["source"] }) {
  const { t } = useI18n();
  return (
    <span className="snapshot-picker__badge" data-imported={source === "imported"}>
      {source === "imported" ? t("snapshots.sourceImported") : t("snapshots.sourceManual")}
    </span>
  );
}

const inputStyle: React.CSSProperties = {
  border: "1px solid var(--line)",
  borderRadius: "var(--radius-sm)",
  padding: "9px 10px",
  fontSize: 13,
  background: "var(--panel)",
  color: "var(--text)",
  width: "100%",
};

const actionButtonStyle: React.CSSProperties = {
  flex: 1,
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: "10px 8px",
  fontSize: 13,
  fontWeight: 700,
};

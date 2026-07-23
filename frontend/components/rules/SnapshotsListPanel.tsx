"use client";

import React, { useRef } from "react";
import { useI18n } from "@/i18n";
import { CURRENT_SNAPSHOT_ID, SnapshotDescriptor, SnapshotOrCurrentId } from "@/lib/types";

interface Props {
  snapshots: SnapshotDescriptor[];
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

  selectedA: SnapshotOrCurrentId;
  selectedB: SnapshotOrCurrentId;
  onSelectA: (id: SnapshotOrCurrentId) => void;
  onSelectB: (id: SnapshotOrCurrentId) => void;
}

function countsTotal(counts: Record<string, number>): number {
  return Object.values(counts).reduce((sum, n) => sum + (typeof n === "number" && Number.isFinite(n) ? n : 0), 0);
}

function formatDate(iso: string, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/** Left-panel control surface for the "Snapshots" workspace tab: the saved
 *  list (create / delete / import) plus the A/B comparison selectors. All
 *  network calls and cross-cutting state (which pair, invalidation on
 *  refresh) live in the parent screen — this component only renders and
 *  reports user intent via callbacks, mirroring the hygiene left panel. */
export function SnapshotsListPanel({
  snapshots,
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
  selectedA,
  selectedB,
  onSelectA,
  onSelectB,
}: Props) {
  const { t, locale } = useI18n();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const options: Array<{ id: SnapshotOrCurrentId; label: string }> = [
    { id: CURRENT_SNAPSHOT_ID, label: t("snapshots.current") },
    ...snapshots.map((s) => ({ id: s.id, label: snapshotOptionLabel(s, locale, t) })),
  ];

  return (
    <div className="check-panel">
      <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{t("snapshots.title")}</div>
      <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5, marginBottom: 14 }}>{t("snapshots.subtitle")}</div>

      {/* ---- compare selectors ---- */}
      <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)", marginBottom: 8 }}>{t("snapshots.compareTitle")}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 16 }}>
        <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--muted)" }}>{t("snapshots.compareA")}</span>
          <select className="form-control" value={selectedA} onChange={(e) => onSelectA(e.target.value)} style={selectStyle}>
            {options.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--muted)" }}>{t("snapshots.compareB")}</span>
          <select className="form-control" value={selectedB} onChange={(e) => onSelectB(e.target.value)} style={selectStyle}>
            {options.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div style={{ height: 1, background: "var(--line)", margin: "16px 0" }} />

      {/* ---- create ---- */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("snapshots.listTitle")}</span>
        <span className="hygiene-nav__count">{t("snapshots.limitCounter", { count: snapshots.length, limit })}</span>
      </div>
      <input
        className="form-control"
        value={comment}
        onChange={(e) => onCommentChange(e.target.value)}
        placeholder={t("snapshots.commentPlaceholder")}
        maxLength={200}
        style={{ ...selectStyle, marginBottom: 8 }}
      />
      <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
        <button type="button" className="btn-primary" onClick={onCreate} disabled={creating || loading} style={actionBtnStyle}>
          {creating ? t("snapshots.creating") : t("snapshots.create")}
        </button>
        <button type="button" className="btn-outline" onClick={() => fileInputRef.current?.click()} disabled={importing} style={actionBtnStyle}>
          {importing ? t("snapshots.importing") : t("snapshots.import")}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept="application/json,.json"
          style={{ display: "none" }}
          onClick={(e) => {
            e.currentTarget.value = "";
          }}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onImportFile(file);
          }}
        />
      </div>
      {importError && (
        <div
          role="alert"
          style={{ fontSize: 12.5, color: "var(--bad)", background: "var(--bad-soft)", borderRadius: "var(--radius-sm)", padding: "9px 11px", marginBottom: 8 }}
        >
          {importError}
        </div>
      )}

      <div style={{ height: 1, background: "var(--line)", margin: "12px 0 14px" }} />

      {/* ---- list ---- */}
      {loading && snapshots.length === 0 ? (
        <div style={{ fontSize: 13, color: "var(--muted)" }}>{t("common.loading")}</div>
      ) : error ? (
        <div role="alert" style={{ fontSize: 13, color: "var(--bad)", background: "var(--bad-soft)", borderRadius: "var(--radius-sm)", padding: "10px 12px" }}>
          {error}
        </div>
      ) : snapshots.length === 0 ? (
        <div style={{ fontSize: 12.5, color: "var(--muted)", lineHeight: 1.5 }}>{t("snapshots.empty")}</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {snapshots.map((s) => (
            <div key={s.id} className="pick-row" style={rowStyle}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 12.5, fontWeight: 700 }}>{formatDate(s.created_at, locale)}</span>
                  <span style={badgeStyle(s.source === "imported" ? "var(--info)" : "var(--muted)")}>
                    {s.source === "imported" ? t("snapshots.sourceImported") : t("snapshots.sourceManual")}
                  </span>
                  {s.foreign_server && <span style={badgeStyle("var(--warn)")}>{t("snapshots.foreignBadge")}</span>}
                </div>
                {s.comment && (
                  <div
                    title={s.comment}
                    style={{ fontSize: 12, color: "var(--muted)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  >
                    {s.comment}
                  </div>
                )}
                <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 2 }}>{t("snapshots.rowCounts", { count: countsTotal(s.counts) })}</div>
              </div>
              <button
                type="button"
                className="btn-ghost"
                aria-label={t("snapshots.delete")}
                title={t("snapshots.delete")}
                onClick={() => onDeleteRequest(s)}
                disabled={deletingId === s.id}
                style={{ flexShrink: 0, fontSize: 13, fontWeight: 700, padding: "4px 8px" }}
              >
                {deletingId === s.id ? "…" : "✕"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function snapshotOptionLabel(s: SnapshotDescriptor, locale: string, t: ReturnType<typeof useI18n>["t"]): string {
  const date = formatDate(s.created_at, locale);
  const tag = s.source === "imported" ? ` (${t("snapshots.sourceImported")})` : "";
  return s.comment ? `${date} — ${s.comment}${tag}` : `${date}${tag}`;
}

const selectStyle: React.CSSProperties = {
  border: "1px solid var(--line)",
  borderRadius: "var(--radius-sm)",
  padding: "9px 10px",
  fontSize: 13,
  background: "var(--panel)",
  color: "var(--text)",
  width: "100%",
};

const actionBtnStyle: React.CSSProperties = {
  flex: 1,
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: "10px 8px",
  fontSize: 13,
  fontWeight: 700,
};

const rowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "flex-start",
  gap: 8,
  border: "1px solid var(--line)",
  borderRadius: "var(--radius-sm)",
  padding: "8px 10px",
  minWidth: 0,
};

function badgeStyle(color: string): React.CSSProperties {
  return {
    fontSize: 10.5,
    fontWeight: 700,
    color,
    border: `1px solid ${color}`,
    borderRadius: 4,
    padding: "1px 5px",
    whiteSpace: "nowrap",
  };
}

import { CURRENT_SNAPSHOT_ID, SnapshotDescriptor, SnapshotOrCurrentId } from "@/lib/types";

/** A comparison side is explicit in the UI so color never carries meaning alone. */
export type SnapshotComparisonSide = "before" | "after";

/** `current` is a selectable live state, not a saved snapshot. */
export interface CurrentSnapshotChoice {
  id: typeof CURRENT_SNAPSHOT_ID;
  source: "current";
  created_at: string;
  rules_updated_at: string;
  comment: null;
  counts: Record<string, number>;
}

export type SnapshotChoice = SnapshotDescriptor | CurrentSnapshotChoice;

/** Build the pinned first item in the picker. Its count is intentionally
 * omitted: the session contract exposes the current load time, not a total
 * object count. Showing no count is more honest than inventing one. */
export function currentSnapshotChoice(rulesUpdatedAt: string | null): CurrentSnapshotChoice {
  return {
    id: CURRENT_SNAPSHOT_ID,
    source: "current",
    created_at: rulesUpdatedAt ?? "",
    rules_updated_at: rulesUpdatedAt ?? "",
    comment: null,
    counts: {},
  };
}

export function findSnapshotChoice(choices: SnapshotChoice[], id: SnapshotOrCurrentId, fallback: SnapshotChoice): SnapshotChoice {
  return choices.find((choice) => choice.id === id) ?? fallback;
}

export function snapshotCountsTotal(counts: Record<string, number>): number {
  return Object.values(counts).reduce((sum, value) => sum + (Number.isFinite(value) ? value : 0), 0);
}

export function formatSnapshotDate(iso: string, locale: string): string {
  if (!iso) return "—";
  try {
    // Seconds distinguish nearby manual snapshots and match the header time.
    return new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "medium" }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/** `file_name` is added by newer backends only for imported snapshots. The
 * intersection keeps the UI compatible with servers which do not send it. */
export function importedSnapshotFileName(snapshot: SnapshotChoice): string | null {
  if (snapshot.source !== "imported") return null;
  const fileName = (snapshot as SnapshotDescriptor & { file_name?: unknown }).file_name;
  return typeof fileName === "string" && fileName.length > 0 ? fileName : null;
}

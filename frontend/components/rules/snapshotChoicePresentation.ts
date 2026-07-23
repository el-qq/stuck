import { importedSnapshotFileName, SnapshotChoice, snapshotCountsTotal, formatSnapshotDate } from "./snapshotComparison";

/** Canonical, user-facing snapshot metadata. Both the picker row and a
 * Before/After target use this shape and order, avoiding two competing
 * explanations of the same selected snapshot. */
export interface SnapshotChoicePresentation {
  title: string;
  /** Shown only when a custom name already occupies the primary position. */
  date: string | null;
  fileName: string | null;
  total: number;
  imported: boolean;
  foreignServer: boolean;
}

export function presentSnapshotChoice(choice: SnapshotChoice, locale: string, currentLabel: string): SnapshotChoicePresentation {
  const imported = choice.source === "imported";
  const fileName = importedSnapshotFileName(choice);
  const total = snapshotCountsTotal(choice.counts);

  if (choice.source === "current") {
    return {
      title: currentLabel,
      date: choice.rules_updated_at ? formatSnapshotDate(choice.rules_updated_at, locale) : null,
      fileName: null,
      total,
      imported: false,
      foreignServer: false,
    };
  }

  const name = choice.comment?.trim() || null;
  const createdAt = formatSnapshotDate(choice.created_at, locale);
  return {
    title: name ?? createdAt,
    date: name ? createdAt : null,
    fileName,
    total,
    imported,
    foreignServer: imported && Boolean(choice.foreign_server),
  };
}

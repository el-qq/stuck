import { SnapshotOrCurrentId } from "./types";

/** A short-lived, non-secret browser convenience. It never contains snapshot
 * names, rules, credentials or either session cookie. */
export interface StoredSnapshotSelection {
  beforeId: SnapshotOrCurrentId;
  afterId: SnapshotOrCurrentId;
  activeSide: "before" | "after";
}

const KEY_PREFIX = "stuck.snapshotSelection.v1";
const MAX_SNAPSHOT_ID_LENGTH = 256;

function keyFor(admin: string, server: string): string {
  return `${KEY_PREFIX}.${encodeURIComponent(admin)}.${encodeURIComponent(server)}`;
}

function isSnapshotId(value: unknown): value is SnapshotOrCurrentId {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_SNAPSHOT_ID_LENGTH;
}

/** Restores only opaque selected ids for this browser tab and one NGFW pair. */
export function getSnapshotSelection(admin: string, server: string): StoredSnapshotSelection | null {
  if (typeof window === "undefined" || !admin || !server) return null;
  try {
    const raw = window.sessionStorage.getItem(keyFor(admin, server));
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      isSnapshotId((parsed as Record<string, unknown>).beforeId) &&
      isSnapshotId((parsed as Record<string, unknown>).afterId) &&
      ((parsed as Record<string, unknown>).activeSide === "before" || (parsed as Record<string, unknown>).activeSide === "after")
    ) {
      return parsed as StoredSnapshotSelection;
    }
  } catch {
    // Storage can be unavailable or user-modified. Fall back to current → current.
  }
  return null;
}

/** Persists only opaque selected ids for the lifetime of the current tab. */
export function setSnapshotSelection(admin: string, server: string, selection: StoredSnapshotSelection): void {
  if (typeof window === "undefined" || !admin || !server) return;
  try {
    window.sessionStorage.setItem(keyFor(admin, server), JSON.stringify(selection));
  } catch {
    // A full or unavailable browser store must not affect comparison behavior.
  }
}

/** Test-visible key construction without exposing it to component code. */
export function snapshotSelectionStorageKey(admin: string, server: string): string {
  return keyFor(admin, server);
}

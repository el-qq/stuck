import { SnapshotDescriptor, SnapshotDiffResponse, SnapshotOrCurrentId } from "@/lib/types";
import type { SnapshotComparisonSide } from "./snapshotComparison";

/** UI contract shared by the live API hook and the fully local demo adapter.
 * Presentation components receive no API client, session or file parser. */
export interface SnapshotWorkspaceState {
  snapshots: SnapshotDescriptor[];
  limit: number;
  loading: boolean;
  error: string | null;
  comment: string;
  setComment: (value: string) => void;
  creating: boolean;
  createSnapshot: () => Promise<void>;
  importing: boolean;
  importError: string | null;
  importSnapshot: (file: File) => Promise<void>;
  deleteTarget: SnapshotDescriptor | null;
  deletingId: string | null;
  deleteError: string | null;
  requestDelete: (snapshot: SnapshotDescriptor) => void;
  cancelDelete: () => void;
  confirmDelete: () => Promise<void>;
  beforeId: SnapshotOrCurrentId;
  afterId: SnapshotOrCurrentId;
  activeSide: SnapshotComparisonSide;
  setActiveSide: (side: SnapshotComparisonSide) => void;
  assign: (side: SnapshotComparisonSide, id: SnapshotOrCurrentId) => void;
  swapSides: () => void;
  diff: SnapshotDiffResponse | null;
  diffLoading: boolean;
  diffError: string | null;
  diffChangeCount: number;
  /** Backend mutations (create/import/delete) are intentionally disabled in demo. */
  backendActionsAvailable: boolean;
}

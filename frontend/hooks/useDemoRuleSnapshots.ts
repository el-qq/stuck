"use client";

import { useCallback, useMemo, useState } from "react";
import { DEMO_CURRENT_SNAPSHOT, DEMO_SNAPSHOT_DIFF, DEMO_SNAPSHOTS, DEMO_SNAPSHOTS_LIMIT } from "@/lib/demoData";
import { getSnapshotSelection, setSnapshotSelection } from "@/lib/snapshotSelectionStorage";
import { CURRENT_SNAPSHOT_ID, SnapshotDescriptor, SnapshotDiffResponse, SnapshotOrCurrentId } from "@/lib/types";
import type { SnapshotWorkspaceState } from "@/components/rules/snapshotWorkspaceState";
import { useSnapshotComparisonSelection, type SnapshotComparisonSelection } from "@/hooks/useSnapshotComparisonSelection";

/** Fully local snapshot adapter. It intentionally has no API/session imports:
 * comparison remains interactive, while persistent snapshot mutations are
 * represented by disabled controls in the shared workspace. */
export function useDemoRuleSnapshots(): SnapshotWorkspaceState {
  const [comment, setComment] = useState("");
  const initialSelection = useMemo(() => getSnapshotSelection("demo", "offline"), []);
  const persistSelection = useCallback((selection: SnapshotComparisonSelection) => setSnapshotSelection("demo", "offline", selection), []);
  const { beforeId, afterId, activeSide, setActiveSide, assign, swapSides } = useSnapshotComparisonSelection({
    initialSelection,
    onSelectionPersist: persistSelection,
  });

  const diff = useMemo<SnapshotDiffResponse | null>(() => {
    if (beforeId === afterId) return null;
    const before = findDemoSide(beforeId);
    const after = findDemoSide(afterId);
    return {
      ...DEMO_SNAPSHOT_DIFF,
      a: asDiffSide(before),
      b: asDiffSide(after),
      comparison_mode: before.source === "imported" || after.source === "imported" ? "anonymized" : "full",
    };
  }, [afterId, beforeId]);

  const noAction = useCallback(async () => undefined, []);
  const noDelete = useCallback((_snapshot: SnapshotDescriptor) => undefined, []);
  const diffChangeCount = diff ? diff.summary.added + diff.summary.removed + diff.summary.changed + diff.summary.moved + diff.summary.states_changed : 0;

  return {
    snapshots: DEMO_SNAPSHOTS,
    limit: DEMO_SNAPSHOTS_LIMIT,
    loading: false,
    error: null,
    comment,
    setComment,
    creating: false,
    createSnapshot: noAction,
    importing: false,
    importError: null,
    importSnapshot: noAction,
    deleteTarget: null,
    deletingId: null,
    deleteError: null,
    requestDelete: noDelete,
    cancelDelete: noAction,
    confirmDelete: noAction,
    beforeId,
    afterId,
    activeSide,
    setActiveSide,
    assign,
    swapSides,
    diff,
    diffLoading: false,
    diffError: null,
    diffChangeCount,
    backendActionsAvailable: false,
  };
}

type DemoSide = typeof DEMO_CURRENT_SNAPSHOT | SnapshotDescriptor;

function findDemoSide(id: SnapshotOrCurrentId): DemoSide {
  if (id === CURRENT_SNAPSHOT_ID) return DEMO_CURRENT_SNAPSHOT;
  return DEMO_SNAPSHOTS.find((snapshot) => snapshot.id === id) ?? DEMO_CURRENT_SNAPSHOT;
}

function asDiffSide(snapshot: DemoSide): SnapshotDiffResponse["a"] {
  return {
    id: snapshot.id,
    created_at: snapshot.created_at,
    rules_updated_at: snapshot.rules_updated_at,
    comment: snapshot.comment,
    source: snapshot.source,
    ...(snapshot.source === "imported" && snapshot.foreign_server ? { foreign_server: true } : {}),
    ...(snapshot.source === "imported" && snapshot.file_name ? { file_name: snapshot.file_name } : {}),
  };
}

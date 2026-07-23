"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useToast } from "@/contexts/ToastContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { ApiError, toApiError } from "@/lib/errors";
import { readFileAsText } from "@/lib/fileRead";
import { getSnapshotSelection, setSnapshotSelection } from "@/lib/snapshotSelectionStorage";
import { CURRENT_SNAPSHOT_ID, SnapshotDescriptor, SnapshotDiffResponse, SnapshotOrCurrentId } from "@/lib/types";
import type { SnapshotWorkspaceState } from "@/components/rules/snapshotWorkspaceState";
import { useSnapshotComparisonSelection, type SnapshotComparisonSelection } from "@/hooks/useSnapshotComparisonSelection";

interface UseRuleSnapshotsOptions {
  /** Only load the list and a diff after its tab becomes visible. */
  active: boolean;
  enabled: boolean;
}

/**
 * Owns all asynchronous snapshot work and the two explicit comparison sides.
 *
 * A monotonically increasing request token makes the state fail closed: a
 * response for an old A/B choice or pre-refresh `current` never replaces the
 * result for the choice now visible to the administrator.
 */
export interface RuleSnapshotsState extends SnapshotWorkspaceState {
  invalidateCurrentDiff: () => void;
}

export function useRuleSnapshots({ active, enabled }: UseRuleSnapshotsOptions): RuleSnapshotsState {
  const session = useSession();
  const toast = useToast();
  const errorMessage = useApiErrorMessage();

  const [snapshots, setSnapshots] = useState<SnapshotDescriptor[]>([]);
  const [limit, setLimit] = useState(10);
  const [listLoaded, setListLoaded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [comment, setComment] = useState("");
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<SnapshotDescriptor | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const [diff, setDiff] = useState<SnapshotDiffResponse | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [currentRevision, setCurrentRevision] = useState(0);
  const diffRequestVersion = useRef(0);

  const clearDiff = useCallback(() => {
    // Invalidate an in-flight request before clearing the visible result.
    diffRequestVersion.current += 1;
    setDiff(null);
    setDiffError(null);
    setDiffLoading(false);
  }, []);

  const snapshotAdmin = session.session?.login ?? "";
  const snapshotServer = session.session?.server ?? "";
  const initialSelection = useMemo(() => getSnapshotSelection(snapshotAdmin, snapshotServer), [snapshotAdmin, snapshotServer]);
  const persistSelection = useCallback(
    (selection: SnapshotComparisonSelection) => setSnapshotSelection(snapshotAdmin, snapshotServer, selection),
    [snapshotAdmin, snapshotServer],
  );

  const { beforeId, afterId, activeSide, setActiveSide, assign, swapSides, resetDeletedSnapshot } = useSnapshotComparisonSelection({
    onSelectionChange: clearDiff,
    initialSelection,
    onSelectionPersist: persistSelection,
  });

  const loadSnapshots = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.listRuleSnapshots();
      setSnapshots(response.snapshots);
      setLimit(response.limit);
      setListLoaded(true);
    } catch (caught) {
      const apiError = toApiError(caught);
      if (session.handleAuthError(apiError)) return;
      setError(errorMessage(apiError));
    } finally {
      setLoading(false);
    }
  }, [errorMessage, session]);

  useEffect(() => {
    if (!listLoaded) return;
    const availableIds = new Set(snapshots.map((snapshot) => snapshot.id));
    // A snapshot can also disappear through another session. Retain the other
    // selected side, but replace a missing side with the safe current state.
    if (beforeId !== CURRENT_SNAPSHOT_ID && !availableIds.has(beforeId)) resetDeletedSnapshot(beforeId);
    if (afterId !== CURRENT_SNAPSHOT_ID && !availableIds.has(afterId)) resetDeletedSnapshot(afterId);
  }, [afterId, beforeId, listLoaded, resetDeletedSnapshot, snapshots]);

  const loadDiff = useCallback(
    async (before: SnapshotOrCurrentId, after: SnapshotOrCurrentId) => {
      const requestVersion = diffRequestVersion.current + 1;
      diffRequestVersion.current = requestVersion;
      setDiffLoading(true);
      setDiffError(null);
      try {
        const response = await api.getRuleSnapshotDiff(before, after);
        if (diffRequestVersion.current !== requestVersion) return;
        setDiff(response);
      } catch (caught) {
        if (diffRequestVersion.current !== requestVersion) return;
        const apiError = toApiError(caught);
        if (session.handleAuthError(apiError)) return;
        setDiffError(errorMessage(apiError));
      } finally {
        if (diffRequestVersion.current === requestVersion) setDiffLoading(false);
      }
    },
    [errorMessage, session],
  );

  useEffect(() => {
    if (active && enabled && !listLoaded && !loading) void loadSnapshots();
    // `loadSnapshots` intentionally does not trigger a reload when context
    // helpers get a new identity; list loading is tied to entering the tab.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, enabled, listLoaded, loading]);

  useEffect(() => {
    if (!active || !enabled || beforeId === afterId) return;
    void loadDiff(beforeId, afterId);
    // See the note on the list effect: selected sides and a live-rules
    // refresh, not context render churn, define a comparison request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, enabled, beforeId, afterId, currentRevision]);

  const createSnapshot = useCallback(async () => {
    setCreating(true);
    try {
      const trimmed = comment.trim();
      await api.createRuleSnapshot(trimmed ? { comment: trimmed } : {});
      setComment("");
      await loadSnapshots();
    } catch (caught) {
      const apiError = toApiError(caught);
      if (!session.handleAuthError(apiError)) toast.show(errorMessage(apiError), "error");
    } finally {
      setCreating(false);
    }
  }, [comment, errorMessage, loadSnapshots, session, toast]);

  const importSnapshot = useCallback(
    async (file: File) => {
      setImportError(null);
      if (file.size > api.SNAPSHOT_IMPORT_MAX_BYTES) {
        setImportError(errorMessage(new ApiError("snapshot_import_too_large", "file too large")));
        return;
      }
      setImporting(true);
      try {
        const text = await readFileAsText(file);
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          setImportError(errorMessage(new ApiError("snapshot_import_invalid", "not valid JSON")));
          return;
        }
        const trimmed = comment.trim();
        // The backend retains only a validated basename for display beside the
        // imported side; no local path or file content metadata is persisted.
        await api.importRuleSnapshot({ export: parsed, file_name: file.name, ...(trimmed ? { comment: trimmed } : {}) });
        setComment("");
        await loadSnapshots();
      } catch (caught) {
        const apiError = toApiError(caught);
        if (session.handleAuthError(apiError)) return;
        setImportError(errorMessage(apiError));
      } finally {
        setImporting(false);
      }
    },
    [comment, errorMessage, loadSnapshots, session],
  );

  const requestDelete = useCallback((snapshot: SnapshotDescriptor) => {
    setDeleteTarget(snapshot);
    setDeleteError(null);
  }, []);

  const cancelDelete = useCallback(() => {
    setDeleteTarget(null);
    setDeleteError(null);
  }, []);

  const confirmDelete = useCallback(async () => {
    if (!deleteTarget) return;
    setDeletingId(deleteTarget.id);
    setDeleteError(null);
    try {
      await api.deleteRuleSnapshot(deleteTarget.id);
      resetDeletedSnapshot(deleteTarget.id);
      setDeleteTarget(null);
      await loadSnapshots();
    } catch (caught) {
      const apiError = toApiError(caught);
      if (session.handleAuthError(apiError)) return;
      setDeleteError(errorMessage(apiError));
    } finally {
      setDeletingId(null);
    }
  }, [deleteTarget, errorMessage, loadSnapshots, resetDeletedSnapshot, session]);

  /** Called after `rules/refresh`. It cancels only a comparison containing
   * `current`; a historical snapshot-to-snapshot diff stays valid. */
  const invalidateCurrentDiff = useCallback(() => {
    if (beforeId === CURRENT_SNAPSHOT_ID || afterId === CURRENT_SNAPSHOT_ID) {
      clearDiff();
      // Re-run an open comparison against the refreshed live rules. The
      // revision is required because the selected ids intentionally stay the
      // same, so they alone cannot trigger the effect above.
      setCurrentRevision((revision) => revision + 1);
    }
  }, [afterId, beforeId, clearDiff]);

  const diffChangeCount = diff ? diff.summary.added + diff.summary.removed + diff.summary.changed + diff.summary.moved + diff.summary.states_changed : 0;

  return {
    snapshots,
    limit,
    loading,
    error,
    comment,
    setComment,
    creating,
    createSnapshot,
    importing,
    importError,
    importSnapshot,
    deleteTarget,
    deletingId,
    deleteError,
    requestDelete,
    cancelDelete,
    confirmDelete,
    beforeId,
    afterId,
    activeSide,
    setActiveSide,
    assign,
    swapSides,
    diff,
    diffLoading,
    diffError,
    invalidateCurrentDiff,
    diffChangeCount,
    backendActionsAvailable: true,
  };
}

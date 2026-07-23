"use client";

import { useCallback, useEffect, useState } from "react";
import { CURRENT_SNAPSHOT_ID, SnapshotOrCurrentId } from "@/lib/types";
import type { SnapshotComparisonSide } from "@/components/rules/snapshotComparison";

export interface SnapshotComparisonSelection {
  beforeId: SnapshotOrCurrentId;
  afterId: SnapshotOrCurrentId;
  activeSide: SnapshotComparisonSide;
}

interface Options {
  /** Invalidates an in-flight or displayed diff before its sides change. */
  onSelectionChange?: () => void;
  /** Restored UI-only selection, validated against the loaded list by the
   * caller. It never carries rule contents or session material. */
  initialSelection?: SnapshotComparisonSelection | null;
  /** Receives only opaque snapshot ids after a user-originated change. */
  onSelectionPersist?: (selection: SnapshotComparisonSelection) => void;
}

/**
 * Owns the two comparison sides independently of snapshot loading or API
 * calls. The initial current → current state guides one first click from
 * Before to After. Once a person explicitly picks a side, it stays active
 * until they choose the other side themselves.
 */
export function useSnapshotComparisonSelection({ onSelectionChange, initialSelection, onSelectionPersist }: Options = {}) {
  const [beforeId, setBeforeId] = useState<SnapshotOrCurrentId>(() => initialSelection?.beforeId ?? CURRENT_SNAPSHOT_ID);
  const [afterId, setAfterId] = useState<SnapshotOrCurrentId>(() => initialSelection?.afterId ?? CURRENT_SNAPSHOT_ID);
  const [activeSide, setActiveSideState] = useState<SnapshotComparisonSide>(() => initialSelection?.activeSide ?? "before");
  const [initialChoicePending, setInitialChoicePending] = useState(() => initialSelection === null || initialSelection === undefined);
  const [persistPending, setPersistPending] = useState(false);

  useEffect(() => {
    if (!persistPending) return;
    onSelectionPersist?.({ beforeId, afterId, activeSide });
    setPersistPending(false);
  }, [activeSide, afterId, beforeId, onSelectionPersist, persistPending]);

  const setActiveSide = useCallback((side: SnapshotComparisonSide) => {
    // Selecting a target card is an explicit choice: do not subsequently
    // switch it behind the user's back after selecting a list row.
    setActiveSideState(side);
    setInitialChoicePending(false);
    setPersistPending(true);
  }, []);

  const assign = useCallback(
    (side: SnapshotComparisonSide, id: SnapshotOrCurrentId) => {
      onSelectionChange?.();
      if (side === "before") setBeforeId(id);
      else setAfterId(id);

      // The default current → current state needs only one guided step. Every
      // later click keeps the explicitly active side stable.
      if (initialChoicePending && side === "before" && beforeId === CURRENT_SNAPSHOT_ID && afterId === CURRENT_SNAPSHOT_ID) {
        setActiveSideState("after");
      }
      setInitialChoicePending(false);
      setPersistPending(true);
    },
    [afterId, beforeId, initialChoicePending, onSelectionChange],
  );

  const swapSides = useCallback(() => {
    onSelectionChange?.();
    setBeforeId(afterId);
    setAfterId(beforeId);
    setActiveSideState("before");
    setInitialChoicePending(false);
    setPersistPending(true);
  }, [afterId, beforeId, onSelectionChange]);

  const resetDeletedSnapshot = useCallback(
    (id: string) => {
      const resetBefore = beforeId === id;
      const resetAfter = afterId === id;
      if (!resetBefore && !resetAfter) return;

      onSelectionChange?.();
      if (resetBefore) setBeforeId(CURRENT_SNAPSHOT_ID);
      if (resetAfter) setAfterId(CURRENT_SNAPSHOT_ID);
      if (resetBefore && resetAfter) {
        setActiveSideState("before");
        setInitialChoicePending(true);
      }
      setPersistPending(true);
    },
    [afterId, beforeId, onSelectionChange],
  );

  return {
    beforeId,
    afterId,
    activeSide,
    setActiveSide,
    assign,
    swapSides,
    resetDeletedSnapshot,
  };
}

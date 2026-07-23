"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { SnapshotDiffView } from "./SnapshotDiffView";
import { SnapshotComparisonTargets } from "./SnapshotComparisonTargets";
import { SnapshotDeleteConfirmModal } from "./SnapshotDeleteConfirmModal";
import { SnapshotsListPanel } from "./SnapshotsListPanel";
import { currentSnapshotChoice, findSnapshotChoice } from "./snapshotComparison";
import type { SnapshotWorkspaceState } from "./snapshotWorkspaceState";

interface Props {
  state: SnapshotWorkspaceState;
  rulesUpdatedAt: string | null;
  port?: number;
}

/** Composes the snapshot management panel and the comparison result. Network
 * state stays in `useRuleSnapshots`; this screen only maps it to visible UI. */
export function SnapshotComparisonWorkspace({ state, rulesUpdatedAt, port }: Props) {
  const { t } = useI18n();
  const current = currentSnapshotChoice(rulesUpdatedAt);
  const choices = [current, ...state.snapshots];
  const before = findSnapshotChoice(choices, state.beforeId, current);
  const after = findSnapshotChoice(choices, state.afterId, current);
  const hasComparison = before.id !== after.id;

  return (
    <>
      <main role="tabpanel" id="tabpanel-snapshots" aria-labelledby="tab-snapshots" className="hygiene-workspace">
        <aside className="hygiene-workspace__controls">
          <SnapshotsListPanel
            choices={choices}
            limit={state.limit}
            loading={state.loading}
            error={state.error}
            comment={state.comment}
            onCommentChange={state.setComment}
            creating={state.creating}
            onCreate={() => void state.createSnapshot()}
            importing={state.importing}
            importError={state.importError}
            onImportFile={(file) => void state.importSnapshot(file)}
            deletingId={state.deletingId}
            onDeleteRequest={state.requestDelete}
            beforeId={state.beforeId}
            afterId={state.afterId}
            activeSide={state.activeSide}
            onAssign={state.assign}
            backendActionsUnavailable={!state.backendActionsAvailable}
          />
        </aside>
        <section className="hygiene-workspace__result">
          <SnapshotComparisonTargets
            before={before}
            after={after}
            activeSide={state.activeSide}
            onActivate={state.setActiveSide}
            onDropChoice={(side, id) => {
              // Do not turn arbitrary drag text into an API snapshot id.
              if (choices.some((choice) => choice.id === id)) state.assign(side, id);
            }}
            onSwap={state.swapSides}
          />

          {state.diffLoading && hasComparison && <div className="snapshot-comparison__loading">{t("snapshots.diffLoading")}</div>}
          {state.diffError && !state.diffLoading && (
            <div role="alert" className="snapshot-comparison__error">
              {state.diffError}
            </div>
          )}
          {state.diff && !state.diffError && (
            <div className="snapshot-comparison__result">
              <SnapshotDiffView diff={state.diff} port={port} />
            </div>
          )}
          {!hasComparison && !state.diffLoading && !state.diffError && (
            <div className="snapshot-comparison__empty">
              <span aria-hidden="true">⇄</span>
              <div>{t("snapshots.selectionEmpty")}</div>
            </div>
          )}
        </section>
      </main>
      <SnapshotDeleteConfirmModal
        snapshot={state.deleteTarget}
        deleting={state.deletingId !== null}
        errorText={state.deleteError}
        onCancel={state.cancelDelete}
        onConfirm={() => void state.confirmDelete()}
      />
    </>
  );
}

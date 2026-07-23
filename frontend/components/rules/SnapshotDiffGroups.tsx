"use client";

import React from "react";
import { useI18n } from "@/i18n";
import type { DiffSide, DiffStateChange, DiffTableGroup } from "@/lib/types";
import { SnapshotDiffEntry } from "./SnapshotDiffEntry";
import { formatDiffValue, stateLabelKey, TABLE_LABEL_KEY } from "./snapshotDiffPresentation";

interface Props {
  groups: DiffTableGroup[];
  states: DiffStateChange[];
  before: DiffSide;
  after: DiffSide;
  server: string;
  port?: number;
  listMaxHeight?: string;
}

export function SnapshotDiffGroups({ groups, states, before, after, server, port, listMaxHeight }: Props) {
  const { t, tOptional } = useI18n();

  return (
    <div className="snapshot-diff__groups" style={listMaxHeight ? { maxHeight: listMaxHeight, overflowY: "auto" } : undefined}>
      {states.length > 0 && (
        <details className="snapshot-diff__group" open>
          <summary>
            {t("snapshots.statesTitle")}
            <span className="snapshot-diff__group-count">{states.length}</span>
          </summary>
          <div className="snapshot-diff__group-body snapshot-diff__state-list">
            {states.map((change, index) => (
              <SnapshotDiffState key={`${change.key}-${index}`} change={change} label={tOptional(stateLabelKey(change.key)) ?? change.key} />
            ))}
          </div>
        </details>
      )}

      {groups.map((group) => {
        const labelKey = TABLE_LABEL_KEY[group.table];
        return (
          <details className="snapshot-diff__group" open key={group.table}>
            <summary>
              {labelKey ? t(labelKey) : group.table}
              <span className="snapshot-diff__group-count">{group.entries.length}</span>
            </summary>
            <div className="snapshot-diff__group-body">
              {group.entries.map((entry, index) => (
                <SnapshotDiffEntry
                  key={`${entry.id}-${entry.kind}-${index}`}
                  entry={entry}
                  table={group.table}
                  before={before}
                  after={after}
                  server={server}
                  port={port}
                />
              ))}
            </div>
          </details>
        );
      })}
    </div>
  );
}

function SnapshotDiffState({ change, label }: { change: DiffStateChange; label: string }) {
  const { t } = useI18n();
  return (
    <div className="snapshot-diff__state">
      <span className="snapshot-diff__state-label">{label}</span>
      <span className="snapshot-diff__state-value">
        <span>{t("snapshots.before")}</span>
        {formatDiffValue(change.from)}
      </span>
      <span className="snapshot-diff__state-value">
        <span>{t("snapshots.after")}</span>
        {formatDiffValue(change.to)}
      </span>
    </div>
  );
}

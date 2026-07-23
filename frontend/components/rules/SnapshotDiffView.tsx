"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { MessageKey } from "@/i18n/en";
import { ngfwRuleSectionUrl } from "@/lib/ngfwRuleLink";
import { DiffEntry, DiffKind, DiffSide, DiffStateChange, DiffSummary, DiffTable, SnapshotDiffResponse, StageKey } from "@/lib/types";

/** Canonical reading order — level 1 (ordered rule tables) then level 3 (objects).
 *  Any table the backend adds later still renders (tolerant, invariant §9),
 *  just appended after the known ones. */
const DIFF_TABLE_ORDER: DiffTable[] = [
  "fw_pre_filter",
  "fw_forward",
  "fw_input",
  "fw_dnat",
  "fw_snat",
  "hw_mac",
  "hw_src_ip",
  "hw_dst_ip",
  "hw_src_dst_ip",
  "cf_rules",
  "shaper_rules",
  "ips_bypass",
  "aliases",
  "users",
];

const TABLE_LABEL_KEY: Partial<Record<DiffTable, MessageKey>> = {
  fw_pre_filter: "snapshots.tableFwPreFilter",
  fw_forward: "snapshots.tableFwForward",
  fw_input: "snapshots.tableFwInput",
  fw_dnat: "snapshots.tableFwDnat",
  fw_snat: "snapshots.tableFwSnat",
  hw_mac: "snapshots.tableHwMac",
  hw_src_ip: "snapshots.tableHwSrcIp",
  hw_dst_ip: "snapshots.tableHwDstIp",
  hw_src_dst_ip: "snapshots.tableHwSrcDstIp",
  cf_rules: "snapshots.tableCfRules",
  shaper_rules: "snapshots.tableShaperRules",
  ips_bypass: "snapshots.tableIpsBypass",
  aliases: "snapshots.tableAliases",
  users: "snapshots.tableUsers",
};

/** The NGFW admin section a table's rules live under, for `ngfwRuleSectionUrl`
 *  (h.4 case 10: `aliases`/`users` and any unmapped table simply get no link). */
const STAGE_BY_DIFF_TABLE: Partial<Record<DiffTable, StageKey>> = {
  fw_pre_filter: "pre_filter",
  fw_forward: "firewall",
  fw_input: "firewall",
  fw_dnat: "dnat",
  fw_snat: "snat",
  hw_mac: "hw_filter",
  hw_src_ip: "hw_filter",
  hw_dst_ip: "hw_filter",
  hw_src_dst_ip: "hw_filter",
  cf_rules: "content_filter",
  shaper_rules: "rate_limit",
  ips_bypass: "ips",
};

export const DIFF_KIND_COLOR: Record<DiffKind, string> = {
  added: "var(--ok)",
  removed: "var(--bad)",
  changed: "var(--warn)",
  moved: "var(--info)",
};

/** Known level-2 state keys (fork c) get a friendly label; anything else the
 *  backend introduces later still renders — falls back to the raw key
 *  (invariant §9, same tolerance as `reason_key`/`title_key`). */
const STATE_LABEL_KEY: Record<string, MessageKey> = {
  fw_state: "snapshots.state.fw_state",
  cf_state: "snapshots.state.cf_state",
  ips_state: "snapshots.state.ips_state",
  av_enabled: "snapshots.state.av_enabled",
  shaper_state: "snapshots.state.shaper_state",
  "hw_settings.mode": "snapshots.state.hw_settings_mode",
  "fw_settings.automatic_snat_enabled": "snapshots.state.fw_settings_automatic_snat_enabled",
};

/** Tab badge color — mirrors `hygieneBadgeColor`: removed/changed rules are the
 *  most consequential class of change, then added/moved/state toggles, then a
 *  clean diff. */
export function diffBadgeColor(summary: Pick<DiffSummary, "added" | "removed" | "changed" | "moved" | "states_changed">): string {
  if (summary.removed > 0 || summary.changed > 0) return "var(--warn)";
  if (summary.added > 0 || summary.moved > 0 || summary.states_changed > 0) return "var(--info)";
  return "var(--ok)";
}

export function DiffSummaryCounters({ summary }: { summary: DiffSummary }) {
  const { t } = useI18n();
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      <Counter color={DIFF_KIND_COLOR.added} label={t("snapshots.countAdded", { count: summary.added })} />
      <Counter color={DIFF_KIND_COLOR.removed} label={t("snapshots.countRemoved", { count: summary.removed })} />
      <Counter color={DIFF_KIND_COLOR.changed} label={t("snapshots.countChanged", { count: summary.changed })} />
      <Counter color={DIFF_KIND_COLOR.moved} label={t("snapshots.countMoved", { count: summary.moved })} />
    </div>
  );
}

function Counter({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12.5, fontWeight: 600 }}>
      <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
      {label}
    </span>
  );
}

interface Props {
  diff: SnapshotDiffResponse;
  /** NGFW HTTPS port for deep links; absent (demo) hides them. */
  port?: number;
  /** Constrain the tables list and scroll inside it (unset lets the page scroll naturally). */
  listMaxHeight?: string;
}

/** Presentational rule-snapshot diff, grouped by table (mirrors
 *  `RuleHygieneReportView`). Shared by the live workspace and the demo tab —
 *  it never fetches anything itself. Renders only text nodes: no
 *  `dangerouslySetInnerHTML` anywhere (h.4 case 10). */
export function SnapshotDiffView({ diff, port, listMaxHeight }: Props) {
  const { t, tOptional } = useI18n();
  const anonymized = diff.comparison_mode === "anonymized";
  const foreignServer = diff.a.foreign_server === true || diff.b.foreign_server === true;
  const noChanges = diff.tables.length === 0 && diff.states.length === 0;

  const known = DIFF_TABLE_ORDER.map((table) => diff.tables.find((g) => g.table === table)).filter((g): g is (typeof diff.tables)[number] => !!g);
  const unknown = diff.tables.filter((g) => !DIFF_TABLE_ORDER.includes(g.table));
  const groups = [...known, ...unknown];

  return (
    <>
      {anonymized && (
        <div role="status" style={bannerStyle("var(--info)", "var(--info-soft)")}>
          {t("snapshots.anonymizedBanner")}
        </div>
      )}
      {foreignServer && (
        <div role="status" style={bannerStyle("var(--warn)", "var(--warn-soft)")}>
          {t("snapshots.foreignServerBanner")}
        </div>
      )}

      <div style={{ margin: "2px 0 14px" }}>
        <DiffSummaryCounters summary={diff.summary} />
      </div>

      {noChanges ? (
        <div
          style={{
            fontSize: 13.5,
            color: "var(--ok)",
            background: "var(--ok-soft)",
            borderRadius: "var(--radius-sm)",
            padding: "14px 16px",
            lineHeight: 1.5,
          }}
        >
          ✓ {t("snapshots.diffClean")}
        </div>
      ) : (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 12,
            ...(listMaxHeight ? { maxHeight: listMaxHeight, overflowY: "auto" } : {}),
          }}
        >
          {diff.states.length > 0 && (
            <details className="hygiene-group" open>
              <summary>
                {t("snapshots.statesTitle")}
                <span className="hygiene-group__count">{diff.states.length}</span>
              </summary>
              <div className="hygiene-group__body">
                {diff.states.map((s, i) => (
                  <StateRow key={`${s.key}-${i}`} change={s} label={tOptional(STATE_LABEL_KEY[s.key]) ?? s.key} />
                ))}
              </div>
            </details>
          )}
          {groups.map((g) => {
            const labelKey = TABLE_LABEL_KEY[g.table];
            const label = labelKey ? t(labelKey) : g.table;
            return (
              <details className="hygiene-group" open key={g.table}>
                <summary>
                  {label}
                  <span className="hygiene-group__count">{g.entries.length}</span>
                </summary>
                <div className="hygiene-group__body">
                  {g.entries.map((entry, i) => (
                    <DiffEntryRow
                      key={`${entry.id}-${entry.kind}-${i}`}
                      entry={entry}
                      table={g.table}
                      a={diff.a}
                      b={diff.b}
                      server={diff.binding.server}
                      port={port}
                    />
                  ))}
                </div>
              </details>
            );
          })}
        </div>
      )}
    </>
  );
}

function bannerStyle(color: string, background: string): React.CSSProperties {
  return {
    fontSize: 13,
    color,
    background,
    borderRadius: "var(--radius-sm)",
    padding: "11px 13px",
    lineHeight: 1.5,
    marginBottom: 12,
  };
}

function StateRow({ change, label }: { change: DiffStateChange; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", fontSize: 12.5 }}>
      <span style={{ fontWeight: 700 }}>{label}</span>
      <span className="mono" style={{ color: "var(--muted)" }}>
        {formatDiffValue(change.from)} → {formatDiffValue(change.to)}
      </span>
    </div>
  );
}

/** Only builds a deep link when the entry can be traced to a "live" side (a
 *  saved manual snapshot or the pair's current state) — never to an id that
 *  only exists in an imported/anonymized document (h.4 case 10). */
function linkSide(entry: DiffEntry, a: DiffSide, b: DiffSide): DiffSide | null {
  if (entry.kind === "added") return b.source !== "imported" ? b : null;
  if (entry.kind === "removed") return a.source !== "imported" ? a : null;
  if (b.source !== "imported") return b;
  if (a.source !== "imported") return a;
  return null;
}

function DiffEntryRow({ entry, table, a, b, server, port }: { entry: DiffEntry; table: DiffTable; a: DiffSide; b: DiffSide; server: string; port?: number }) {
  const { t } = useI18n();
  const color = DIFF_KIND_COLOR[entry.kind];
  const side = linkSide(entry, a, b);
  const stage = STAGE_BY_DIFF_TABLE[table];
  const link = side && stage ? ngfwRuleSectionUrl(server, port, stage, entry.id) : null;

  return (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        background: "var(--panel2)",
        borderRadius: "var(--radius-sm)",
        padding: "11px 13px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13.5, fontWeight: 700, color }}>{kindLabel(t, entry.kind)}</span>
        <span className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
          {positionLabel(t, entry)} · id={entry.id}
          {link ? " ·" : ""}
        </span>
        {link && (
          <a href={link} target="_blank" rel="noopener noreferrer" style={{ fontSize: 11.5, fontWeight: 600, color: "var(--accent)" }}>
            {t("common.openNgfwSection")} ↗
          </a>
        )}
      </div>
      {entry.name && (
        <div
          title={entry.name}
          style={{
            fontSize: 12.5,
            fontWeight: 600,
            color: "color-mix(in srgb, var(--text) 60%, transparent)",
            margin: "4px 0 7px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            maxWidth: "100%",
          }}
        >
          «{entry.name}»
        </div>
      )}
      {entry.changed_fields && entry.changed_fields.length > 0 && (
        <div style={{ marginTop: entry.name ? 0 : 4, display: "flex", flexDirection: "column", gap: 3 }}>
          {entry.changed_fields.map((f) => (
            <div key={f.field} className="mono" style={{ fontSize: 12, color: "var(--text)", overflowWrap: "anywhere" }}>
              <span style={{ fontWeight: 700 }}>{f.field}</span>: {formatDiffValue(f.from)} → {formatDiffValue(f.to)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type TFn = ReturnType<typeof useI18n>["t"];

function kindLabel(t: TFn, kind: DiffKind): string {
  switch (kind) {
    case "added":
      return t("snapshots.kindAdded");
    case "removed":
      return t("snapshots.kindRemoved");
    case "changed":
      return t("snapshots.kindChanged");
    case "moved":
      return t("snapshots.kindMoved");
  }
}

function positionLabel(t: TFn, e: DiffEntry): string {
  if (e.kind === "added") return t("snapshots.positionAdded", { position: e.position_b ?? "?" });
  if (e.kind === "removed") return t("snapshots.positionRemoved", { position: e.position_a ?? "?" });
  return t("snapshots.positionBoth", { a: e.position_a ?? "?", b: e.position_b ?? "?" });
}

/** Safe, bounded stringification of an unknown JSON value for side-by-side
 *  display — never rendered as HTML, always a plain text node. */
function formatDiffValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    const s = JSON.stringify(v);
    return s.length > 160 ? `${s.slice(0, 160)}…` : s;
  } catch {
    return String(v);
  }
}

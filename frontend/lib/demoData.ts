/**
 * Offline demo mode (iteration 4). Fully self-contained: no backend, no login,
 * no /api/* calls — lets someone without NGFW access see the app working.
 *
 * Data is maintained as a small production fixture. The local demo engine
 * below produces the same
 * contract-shaped TraceResponse the real backend would, so the pipeline
 * animation and result view are reused unchanged.
 */

import { NgfwUser, RuleHygieneReport, SnapshotDescriptor, SnapshotDiffResponse, StageKey, StageStatus, TraceResponse, TraceStage, STAGE_ORDER } from "./types";
import { MessageKey } from "@/i18n/en";

/**
 * The two selectable demo targets (iteration 5). The outcome is determined by
 * the target: success → allowed, failure → blocked. Shown in the "recent
 * addresses" block; the address field itself stays read-only in demo mode.
 */
export interface DemoTarget {
  /** Display + selection value, e.g. "success.com:443". */
  address: string;
  host: string;
  dst_port: number;
  resolved_ip: string;
  outcome: "allowed" | "blocked";
}

export const DEMO_TARGETS: DemoTarget[] = [
  { address: "success.com:443", host: "success.com", dst_port: 443, resolved_ip: "203.0.113.10", outcome: "allowed" },
  { address: "failure.com:8080", host: "failure.com", dst_port: 8080, resolved_ip: "203.0.113.55", outcome: "blocked" },
];

/** Default selected target (iteration 5 #3). */
export const DEFAULT_DEMO_TARGET = DEMO_TARGETS[0]!;

export interface DemoGroup {
  id: string;
  name: string;
}

export const DEMO_GROUPS: DemoGroup[] = [
  { id: "g-admins", name: "Administrators" },
  { id: "g-it", name: "IT department" },
  { id: "g-buh", name: "Accounting" },
  { id: "g-sales", name: "Sales" },
  { id: "g-guests", name: "Wi-Fi guests" },
];

/** Demo users, shaped as the contract's NgfwUser so UserPicker works as-is. */
export const DEMO_USERS: NgfwUser[] = [
  { id: "u1", login: "a.ivanov", name: "Alexey Ivanov", enabled: true, domain_type: "local", group_id: "g-admins" },
  { id: "u2", login: "s.petrova", name: "Svetlana Petrova", enabled: true, domain_type: "local", group_id: "g-buh" },
  { id: "u3", login: "d.sidorov", name: "Dmitry Sidorov", enabled: true, domain_type: "local", group_id: "g-it" },
  { id: "u4", login: "m.kuznetsova", name: "Maria Kuznetsova", enabled: true, domain_type: "local", group_id: "g-sales" },
  { id: "u5", login: "o.smirnov", name: "Oleg Smirnov", enabled: true, domain_type: "local", group_id: "g-sales" },
  { id: "u6", login: "guest-204", name: "Guest #204", enabled: false, domain_type: "local", group_id: "g-guests" },
];

type StageSpec = Partial<Record<StageKey, { status: StageStatus; detail?: TraceStage["detail"] }>>;

interface Scenario {
  blockedAt: StageKey | null;
  stages: StageSpec;
}

/**
 * The allowed scenario: all stages pass cleanly, traffic reaches the
 * destination. The firewall stage names the matched rule for realism.
 */
const ALLOWED_SCENARIO: Scenario = {
  blockedAt: null,
  stages: {
    firewall: {
      status: "pass",
      detail: { rule_id: "fw8", rule_name: "Internet for everyone (basic)", action: "accept", reason_key: "fw_rule_matched" },
    },
  },
};

/**
 * The blocked scenario for failure.com:8080 — the firewall drops the
 * connection because of the non-standard port 8080. Stages after the block
 * become `na`/blocked_upstream (handled below).
 */
const BLOCKED_SCENARIO: Scenario = {
  blockedAt: "firewall",
  stages: {
    content_filter: { status: "pass", detail: { reason_key: "cf_default_allow", module_enabled: true } },
    firewall: {
      status: "block",
      detail: {
        rule_id: "fw9",
        rule_name: "Default deny (non-standard ports)",
        action: "drop",
        reason_key: "fw_rule_matched",
      },
    },
  },
};

/**
 * Local demo engine (iteration 5): the OUTCOME is decided by the selected
 * target — success.com:443 → allowed, failure.com:8080 → blocked. The chosen
 * user is reflected in the result but does not change the ok/error verdict.
 * `t` localizes the free-text category label; stage titles/reasons stay as
 * i18n keys the UI already knows how to render.
 */
export function runDemoTrace(target: DemoTarget, user: NgfwUser | null, t: (key: MessageKey) => string): TraceResponse {
  const scenario = target.outcome === "blocked" ? BLOCKED_SCENARIO : ALLOWED_SCENARIO;
  const blockIndex = scenario.blockedAt ? STAGE_ORDER.indexOf(scenario.blockedAt) : -1;

  const stages: TraceStage[] = STAGE_ORDER.map((key, i) => {
    const spec = scenario.stages[key];
    let status: StageStatus;
    let detail = spec?.detail;
    if (spec) {
      status = spec.status;
    } else if (blockIndex !== -1 && i > blockIndex) {
      // Everything after the block point is not reached.
      status = "na";
      detail = { reason_key: "blocked_upstream" };
    } else if (key === "destination") {
      status = blockIndex === -1 ? "pass" : "na";
    } else {
      status = "pass";
    }
    return { key, order: i + 1, title_key: `stage.${key}`, status, ...(detail ? { detail } : {}) };
  });

  const blocked = scenario.blockedAt !== null;

  return {
    target: {
      input: target.address,
      normalized_url: target.host,
      host: target.host,
      resolved_ip: target.resolved_ip,
      source_ip: user ? "192.0.2.100" : null,
      dst_port: target.dst_port,
      protocol: "tcp",
      effective_destination_ip: target.resolved_ip,
      effective_destination_port: target.dst_port,
    },
    user: user ? { id: user.id, name: user.name, login: user.login } : null,
    categories: [],
    stages,
    summary: {
      reached_destination: !blocked,
      blocked_at: scenario.blockedAt,
      verdict: blocked ? "blocked" : "allowed",
    },
    rules_updated_at: DEMO_RULES_UPDATED_AT,
  };
}

/** Stable timestamp shown as "rules updated" in demo mode. */
export const DEMO_RULES_UPDATED_AT = "2026-01-01T09:00:00Z";

/**
 * Offline rule-hygiene report. Mirrors the shape and the SEMANTICS of
 * GET /api/rules/hygiene: one example of every finding kind, both firewall
 * chains, and both tiers (a `possible` finding sits behind an opaque schedule
 * condition). Within one chain the grouping matches the real analyser — a
 * catch-all groups everything after it instead of per-rule shadow findings.
 * Rule names are plain NGFW comments, like the demo trace rule names.
 */
export const DEMO_HYGIENE_REPORT: RuleHygieneReport = {
  binding: { admin: "demo", server: "demo.local" },
  rules_updated_at: DEMO_RULES_UPDATED_AT,
  generated_at: DEMO_RULES_UPDATED_AT,
  summary: { total: 7, risk: 1, warning: 4, info: 2, possible: 1 },
  findings: [
    {
      kind: "hw_inactive",
      severity: "warning",
      tier: "certain",
      table: "hw_filter",
      reason_key: "hygiene_hw_inactive",
      rule: { id: "hwd1", name: "Block scanner (old)", position: 1 },
      related: [{ id: "hwd2", name: "Block bruteforce (old)", position: 2 }],
      extra: { inactive_count: 2, list_mode: "dst-ip", active_mode: "src-ip" },
    },
    {
      kind: "redundant",
      severity: "info",
      tier: "certain",
      table: "hw_filter",
      reason_key: "hygiene_hw_duplicate",
      rule: { id: "hws3", name: "Drop 203.0.113.66 (again)", position: 3 },
      related: [{ id: "hws1", name: "Drop 203.0.113.66", position: 1 }],
    },
    {
      kind: "overly_broad",
      severity: "risk",
      tier: "certain",
      table: "fw_input",
      reason_key: "hygiene_overly_broad",
      rule: { id: "in1", name: "TEMP: allow any→any (debug)", position: 1 },
      related: [],
    },
    {
      kind: "unreachable_after_any",
      severity: "warning",
      tier: "certain",
      table: "fw_input",
      reason_key: "hygiene_unreachable_after_any",
      rule: { id: "in1", name: "TEMP: allow any→any (debug)", position: 1 },
      related: [
        { id: "in2", name: "Allow admin HTTPS from LAN", position: 2 },
        { id: "in3", name: "Drop the rest", position: 3 },
      ],
      extra: { unreachable_count: 2 },
    },
    {
      kind: "shadowed",
      severity: "warning",
      tier: "certain",
      table: "fw_forward",
      reason_key: "hygiene_shadowed",
      rule: { id: "fw7", name: "Deny social networks for Sales", position: 7 },
      related: [{ id: "fw2", name: "Allow web for office LAN", position: 2 }],
    },
    {
      kind: "shadowed",
      severity: "warning",
      tier: "possible",
      table: "fw_forward",
      reason_key: "hygiene_shadowed",
      rule: { id: "fw11", name: "Deny FTP at night", position: 11 },
      related: [{ id: "fw6", name: "Allow FTP for IT (work hours)", position: 6 }],
    },
    {
      kind: "redundant",
      severity: "info",
      tier: "certain",
      table: "fw_forward",
      reason_key: "hygiene_redundant",
      rule: { id: "fw9", name: "Allow DNS to gateway (duplicate)", position: 9 },
      related: [{ id: "fw4", name: "Allow DNS to gateway", position: 4 }],
    },
  ],
};

/**
 * Offline rule-snapshots showcase (docs/source/snapshots.md, fork f). Mirrors
 * the shape of GET /api/rules/snapshots: one manual snapshot and one imported
 * (foreign-server) snapshot, so the panel and its badges render exactly as
 * the live workspace would — no backend, no /api/* calls.
 */
export const DEMO_SNAPSHOTS_LIMIT = 10;

/** The pinned first item of the demo selector.  It mirrors the live rules
 * snapshot, but deliberately stays outside the saved-snapshot list. */
export const DEMO_CURRENT_SNAPSHOT = {
  id: "current",
  created_at: DEMO_RULES_UPDATED_AT,
  rules_updated_at: DEMO_RULES_UPDATED_AT,
  comment: null,
  source: "current" as const,
  counts: { users: 6, firewall_forward: 10, firewall_input: 3, content_filter_rules: 4, hardware_rules: 5, aliases: 3 },
};

export const DEMO_SNAPSHOTS: SnapshotDescriptor[] = [
  {
    id: "demo-snap-yesterday",
    created_at: "2026-01-01T09:00:00Z",
    rules_updated_at: "2026-01-01T09:00:00Z",
    comment: "Before the morning maintenance window",
    source: "manual",
    counts: { users: 6, firewall_forward: 9, firewall_input: 3, content_filter_rules: 4, hardware_rules: 5, aliases: 3 },
  },
  {
    id: "demo-snap-imported",
    created_at: "2025-12-20T08:00:00Z",
    rules_updated_at: "2025-12-20T07:55:00Z",
    exported_at: "2025-12-20T07:56:00Z",
    comment: "Reference export from the staging NGFW",
    source: "imported",
    file_name: "staging-rules-2025-12-20.json",
    server: "staging-ngfw.example",
    foreign_server: true,
    counts: { users: 4, firewall_forward: 6, firewall_input: 2, content_filter_rules: 3, hardware_rules: 4, aliases: 2 },
  },
];

/**
 * Offline diff (fork c/f/h): compares the imported (foreign-server) snapshot
 * above against "current" — the one static example shows every diff kind
 * (added/removed/changed/moved), a level-2 state toggle, AND both the
 * `anonymized` and `foreign_server` banners at once, like the hygiene
 * fixture packs every finding kind into a single screen.
 */
export const DEMO_SNAPSHOT_DIFF: SnapshotDiffResponse = {
  binding: { admin: "demo", server: "demo.local" },
  a: {
    id: "demo-snap-imported",
    created_at: "2025-12-20T08:00:00Z",
    rules_updated_at: "2025-12-20T07:55:00Z",
    comment: "Reference export from the staging NGFW",
    source: "imported",
    foreign_server: true,
    file_name: "staging-rules-2025-12-20.json",
  },
  b: {
    id: "current",
    created_at: DEMO_RULES_UPDATED_AT,
    rules_updated_at: DEMO_RULES_UPDATED_AT,
    comment: null,
    source: "current",
  },
  generated_at: DEMO_RULES_UPDATED_AT,
  comparison_mode: "anonymized",
  summary: { added: 1, removed: 1, changed: 2, moved: 1, states_changed: 1, tables_changed: 3 },
  tables: [
    {
      table: "fw_forward",
      entries: [
        { kind: "added", id: "fw12", name: "Allow VPN subnet to internet", position_a: null, position_b: 8 },
        {
          kind: "changed",
          id: "fw7",
          name: "Deny social networks for Sales",
          position_a: 7,
          position_b: 6,
          changed_fields: [{ field: "destinations", from: ["cat:social"], to: ["cat:social", "cat:streaming"] }],
        },
        { kind: "moved", id: "fw2", name: "Allow web for office LAN", position_a: 2, position_b: 1 },
      ],
    },
    {
      table: "fw_input",
      entries: [{ kind: "removed", id: "in9", name: "Temporary debug access", position_a: 9, position_b: null }],
    },
    {
      table: "aliases",
      entries: [
        {
          kind: "changed",
          id: "alias-office-lan",
          name: "Office LAN",
          position_a: 1,
          position_b: 1,
          changed_fields: [{ field: "value", from: "192.168.10.0/24", to: "192.168.10.0/23" }],
        },
      ],
    },
  ],
  states: [{ key: "ips_state", from: true, to: false }],
};

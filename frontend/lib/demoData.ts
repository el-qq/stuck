/**
 * Offline demo mode (iteration 4). Fully self-contained: no backend, no login,
 * no /api/* calls — lets someone without NGFW access see the app working.
 *
 * Data is maintained as a small production fixture. The local demo engine
 * below produces the same
 * contract-shaped TraceResponse the real backend would, so the pipeline
 * animation and result view are reused unchanged.
 */

import {
  CompareResponse,
  CompareSide,
  NgfwUser,
  Protocol,
  RuleHygieneReport,
  SnapshotDescriptor,
  SnapshotDiffResponse,
  StageKey,
  StageStatus,
  TraceResponse,
  TraceStage,
  UserSourceAddress,
  STAGE_ORDER,
} from "./types";
import { classifyCompareStages } from "./accessCompare";
import { MessageKey } from "@/i18n/en";
import { parseTarget } from "./servicePresets";

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

/** Static source choices make the demo use the same user scenario controls as
 * the live workspace. They are examples only and never originate from NGFW. */
export const DEMO_SOURCE_ADDRESSES: Record<string, UserSourceAddress[]> = {
  u1: [{ ip: "192.0.2.101", subnet: "192.0.2.0/24", external_ip: null, auth_module: "demo", node_name: "demo-lan", active: true, assigned: true }],
  u2: [
    { ip: "192.0.2.102", subnet: "192.0.2.0/24", external_ip: null, auth_module: "demo", node_name: "demo-lan", active: true, assigned: true },
    { ip: "198.51.100.102", subnet: "198.51.100.0/24", external_ip: null, auth_module: "demo", node_name: "demo-wifi", active: true, assigned: false },
  ],
  u3: [{ ip: "192.0.2.103", subnet: "192.0.2.0/24", external_ip: null, auth_module: "demo", node_name: "demo-lan", active: true, assigned: true }],
  u4: [{ ip: "192.0.2.104", subnet: "192.0.2.0/24", external_ip: null, auth_module: "demo", node_name: "demo-lan", active: true, assigned: true }],
  u5: [{ ip: "192.0.2.105", subnet: "192.0.2.0/24", external_ip: null, auth_module: "demo", node_name: "demo-lan", active: true, assigned: true }],
  u6: [],
};

/** Map form input to a deterministic local fixture. Unknown targets use the
 * allowed example; demo mode never claims to query a real NGFW policy. */
export function demoTargetForInput(raw: string): DemoTarget {
  const parsed = parseTarget(raw);
  const host = parsed.host || raw.trim();
  const port = parsed.port ?? 443;
  return (
    DEMO_TARGETS.find((target) => target.host === host && target.dst_port === port) ?? {
      address: port ? `${host}:${port}` : host,
      host,
      dst_port: port,
      resolved_ip: "203.0.113.10",
      outcome: "allowed",
    }
  );
}

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
 * Builds the fixed 12-stage pipeline for one scenario, optionally overlaying
 * a few stage results on top (used by the access-compare engine below to
 * honestly mark IP-dependent stages `unknown` for a subject with no resolved
 * source IP — invariant №7 — without duplicating this block-cascade logic).
 */
function buildScenarioStages(scenario: Scenario, overrides?: StageSpec): TraceStage[] {
  const merged: StageSpec = overrides ? { ...scenario.stages, ...overrides } : scenario.stages;
  const blockIndex = scenario.blockedAt ? STAGE_ORDER.indexOf(scenario.blockedAt) : -1;

  return STAGE_ORDER.map((key, i) => {
    const spec = merged[key];
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
}

/**
 * Local demo engine (iteration 5): the OUTCOME is decided by the selected
 * target — success.com:443 → allowed, failure.com:8080 → blocked. The chosen
 * user is reflected in the result but does not change the ok/error verdict.
 * `t` localizes the free-text category label; stage titles/reasons stay as
 * i18n keys the UI already knows how to render.
 */
export function runDemoTrace(
  target: DemoTarget,
  user: NgfwUser | null,
  t: (key: MessageKey) => string,
  sourceIp?: string,
  protocol: Protocol = "any",
): TraceResponse {
  const scenario = target.outcome === "blocked" ? BLOCKED_SCENARIO : ALLOWED_SCENARIO;
  const stages = buildScenarioStages(scenario);
  const blocked = scenario.blockedAt !== null;

  return {
    target: {
      input: target.address,
      normalized_url: target.host,
      host: target.host,
      resolved_ip: target.resolved_ip,
      source_ip: user ? (sourceIp ?? "192.0.2.100") : null,
      dst_port: target.dst_port,
      protocol,
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

/**
 * Offline access-compare showcase (docs/source/comparison.md). A single fixed
 * scenario — not driven by pickers — that packs every classification the
 * feature can produce into one screen, the same way the hygiene/snapshot
 * fixtures above pack every finding/diff kind into one example:
 *
 * - Side A: an office user with an assigned source IP (all context present).
 * - Side B: a Wi-Fi guest with NO active/assigned IP (`context.has_source_ip`
 *   is false) — so the IP-dependent early stages are honestly `unknown`,
 *   never guessed (invariant №7).
 *
 * Coverage: `same` (dns, dnat, antivirus), `divergent` with
 * `same_status_different_rule` (content_filter — both sides pass, but via a
 * different rule) as the `primary_divergence`, `divergent` with a `block`
 * (firewall, `blocking_side: "b"`), and `incomparable` for both the
 * IP-dependent early stages AND the stages after B's block (case i.9: a
 * later `na` following an earlier block is "incomparable", not a fresh
 * "difference"). The classification itself is computed by the same
 * `classifyCompareStages` the demo never otherwise needs (see lib/accessCompare.ts).
 */
function demoCompareStage(key: StageKey, status: StageStatus, detail?: TraceStage["detail"]): TraceStage {
  return { key, order: STAGE_ORDER.indexOf(key) + 1, title_key: `stage.${key}`, status, ...(detail ? { detail } : {}) };
}

const DEMO_COMPARE_TARGET = { host: "reports.corp.local", dst_port: 443, resolved_ip: "10.20.0.15" };

const DEMO_COMPARE_STAGES_A: TraceStage[] = [
  demoCompareStage("hw_filter", "pass", { hw_mode: "src-ip", reason_key: "hw_no_matching_rule" }),
  demoCompareStage("pre_filter", "pass", { reason_key: "pre_filter_no_matching_rule" }),
  demoCompareStage("rate_limit", "pass", { reason_key: "rate_limit_no_matching_rule", module_enabled: true }),
  demoCompareStage("dns", "resolved", { resolved_ip: DEMO_COMPARE_TARGET.resolved_ip }),
  demoCompareStage("dnat", "skip", { reason_key: "dnat_disabled" }),
  demoCompareStage("content_filter", "pass", { rule_id: "cf12", rule_name: "Allow business categories", action: "accept" }),
  demoCompareStage("antivirus", "active", { reason_key: "av_active_content_unknown", module_enabled: true }),
  demoCompareStage("firewall", "pass", { rule_id: "fw4", rule_name: "Allow office LAN to internal apps", action: "accept", reason_key: "fw_rule_accept" }),
  demoCompareStage("app_control", "skip", { reason_key: "dpi_disabled_in_rule" }),
  demoCompareStage("ips", "active", { module_enabled: true }),
  demoCompareStage("snat", "active", { reason_key: "snat_automatic_active" }),
  demoCompareStage("destination", "pass"),
];

const DEMO_COMPARE_STAGES_B: TraceStage[] = [
  demoCompareStage("hw_filter", "unknown", { reason_key: "hw_source_ip_unknown" }),
  demoCompareStage("pre_filter", "unknown", { reason_key: "pre_filter_source_unknown" }),
  demoCompareStage("rate_limit", "unknown", { reason_key: "source_ip_unknown" }),
  demoCompareStage("dns", "resolved", { resolved_ip: DEMO_COMPARE_TARGET.resolved_ip }),
  demoCompareStage("dnat", "skip", { reason_key: "dnat_disabled" }),
  demoCompareStage("content_filter", "pass", { rule_id: "cf20", rule_name: "Allow default web for guests", action: "accept" }),
  demoCompareStage("antivirus", "active", { reason_key: "av_active_content_unknown", module_enabled: true }),
  demoCompareStage("firewall", "block", { rule_id: "fw9", rule_name: "Default deny for guest network", action: "drop", reason_key: "fw_rule_blocked" }),
  demoCompareStage("app_control", "na", { reason_key: "blocked_upstream" }),
  demoCompareStage("ips", "na", { reason_key: "blocked_upstream" }),
  demoCompareStage("snat", "na", { reason_key: "blocked_upstream" }),
  demoCompareStage("destination", "na", { reason_key: "blocked_upstream" }),
];

function demoCompareSide(
  user: { id: string; name: string; login: string } | null,
  sourceIp: string | null,
  summary: { reached_destination: boolean; blocked_at: StageKey | null; verdict: "allowed" | "blocked" },
): CompareSide {
  return {
    subject: { user, source_ip: sourceIp },
    context: { has_user: user !== null, has_source_ip: sourceIp !== null },
    target: {
      input: `${DEMO_COMPARE_TARGET.host}:${DEMO_COMPARE_TARGET.dst_port}`,
      normalized_url: DEMO_COMPARE_TARGET.host,
      host: DEMO_COMPARE_TARGET.host,
      resolved_ip: DEMO_COMPARE_TARGET.resolved_ip,
      source_ip: sourceIp,
      dst_port: DEMO_COMPARE_TARGET.dst_port,
      protocol: "tcp",
      effective_destination_ip: DEMO_COMPARE_TARGET.resolved_ip,
      effective_destination_port: DEMO_COMPARE_TARGET.dst_port,
    },
    summary,
  };
}

const {
  stages: DEMO_COMPARE_STAGES,
  primary_divergence: DEMO_COMPARE_PRIMARY_DIVERGENCE,
  divergence_reason: DEMO_COMPARE_DIVERGENCE_REASON,
} = classifyCompareStages(DEMO_COMPARE_STAGES_A, DEMO_COMPARE_STAGES_B);

export const DEMO_ACCESS_COMPARE: CompareResponse = {
  binding: { admin: "demo", server: "demo.local" },
  target_input: { url: `${DEMO_COMPARE_TARGET.host}:${DEMO_COMPARE_TARGET.dst_port}`, protocol: "tcp", dst_port: DEMO_COMPARE_TARGET.dst_port },
  a: demoCompareSide({ id: "u2", name: "Svetlana Petrova", login: "s.petrova" }, "192.0.2.102", {
    reached_destination: true,
    blocked_at: null,
    verdict: "allowed",
  }),
  b: demoCompareSide({ id: "u6", name: "Guest #204", login: "guest-204" }, null, { reached_destination: false, blocked_at: "firewall", verdict: "blocked" }),
  categories: ["business-apps"],
  stages: DEMO_COMPARE_STAGES,
  primary_divergence: DEMO_COMPARE_PRIMARY_DIVERGENCE,
  divergence_reason: DEMO_COMPARE_DIVERGENCE_REASON,
  identical_subjects: false,
  rules_updated_at: DEMO_RULES_UPDATED_AT,
  generated_at: DEMO_RULES_UPDATED_AT,
};

/**
 * Interactive local access-compare engine (`useDemoAccessCompare`), used once
 * the administrator edits the compare form and runs it — as opposed to
 * `DEMO_ACCESS_COMPARE` above, the hand-built showcase pre-loaded as that
 * tab's initial result. It follows the exact same philosophy `runDemoTrace`
 * already established for the check tab: the shared TARGET decides the
 * pass/block outcome, identically for both sides (comparing two different
 * targets is out of scope per the contract). The only thing that genuinely
 * varies per side here is CONTEXT completeness: a side with no resolved
 * source IP honestly reports the IP-dependent early stages as `unknown`
 * (invariant №7), same as the static showcase's Side B.
 *
 * What this does NOT attempt to model: a subject changing which content-filter
 * or firewall RULE matches (the `same_status_different_rule`/`divergent`
 * outcomes the showcase above demonstrates). That depends on NGFW rule
 * matching, which is backend domain logic — duplicating it here would drift
 * from the real engine over time, not stay a small offline fixture.
 */
const IP_UNKNOWN_OVERRIDE: StageSpec = {
  hw_filter: { status: "unknown", detail: { reason_key: "hw_source_ip_unknown" } },
  pre_filter: { status: "unknown", detail: { reason_key: "pre_filter_source_unknown" } },
  rate_limit: { status: "unknown", detail: { reason_key: "source_ip_unknown" } },
};

export interface DemoCompareSubject {
  user: NgfwUser | null;
  sourceIp: string | null;
}

function demoCompareSideFromSubject(subject: DemoCompareSubject, target: DemoTarget, protocol: Protocol, stages: TraceStage[]): CompareSide {
  const blockedStage = stages.find((stage) => stage.status === "block") ?? null;
  return {
    subject: { user: subject.user ? { id: subject.user.id, name: subject.user.name, login: subject.user.login } : null, source_ip: subject.sourceIp },
    context: { has_user: subject.user !== null, has_source_ip: subject.sourceIp !== null },
    target: {
      input: target.address,
      normalized_url: target.host,
      host: target.host,
      resolved_ip: target.resolved_ip,
      source_ip: subject.sourceIp,
      dst_port: target.dst_port,
      protocol,
      effective_destination_ip: target.resolved_ip,
      effective_destination_port: target.dst_port,
    },
    summary: {
      reached_destination: blockedStage === null,
      blocked_at: blockedStage?.key ?? null,
      verdict: blockedStage === null ? "allowed" : "blocked",
    },
  };
}

export function runDemoCompare(urlInput: string, protocol: Protocol, subjectA: DemoCompareSubject, subjectB: DemoCompareSubject): CompareResponse {
  const target = demoTargetForInput(urlInput);
  const scenario = target.outcome === "blocked" ? BLOCKED_SCENARIO : ALLOWED_SCENARIO;
  const stagesA = buildScenarioStages(scenario, subjectA.sourceIp !== null ? undefined : IP_UNKNOWN_OVERRIDE);
  const stagesB = buildScenarioStages(scenario, subjectB.sourceIp !== null ? undefined : IP_UNKNOWN_OVERRIDE);
  const { stages, primary_divergence, divergence_reason } = classifyCompareStages(stagesA, stagesB);
  // Response-level precedence (docs/source/comparison.md §3.e): identical
  // subjects override the stage-level reason with "identical", mirroring the
  // backend's `_divergence_reason` — stage classification alone cannot tell
  // "nothing differs" apart from "both sides are literally the same ask".
  const identicalSubjects = (subjectA.user?.id ?? null) === (subjectB.user?.id ?? null) && subjectA.sourceIp === subjectB.sourceIp;

  return {
    binding: { admin: "demo", server: "demo.local" },
    target_input: { url: urlInput, protocol, dst_port: target.dst_port },
    a: demoCompareSideFromSubject(subjectA, target, protocol, stagesA),
    b: demoCompareSideFromSubject(subjectB, target, protocol, stagesB),
    categories: [],
    stages,
    primary_divergence,
    divergence_reason: identicalSubjects ? "identical" : divergence_reason,
    identical_subjects: identicalSubjects,
    rules_updated_at: DEMO_RULES_UPDATED_AT,
    generated_at: DEMO_RULES_UPDATED_AT,
  };
}

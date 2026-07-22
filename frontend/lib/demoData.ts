/**
 * Offline demo mode (iteration 4). Fully self-contained: no backend, no login,
 * no /api/* calls — lets someone without NGFW access see the app working.
 *
 * Data is maintained as a small production fixture. The local demo engine
 * below produces the same
 * contract-shaped TraceResponse the real backend would, so the pipeline
 * animation and result view are reused unchanged.
 */

import { NgfwUser, RuleHygieneReport, StageKey, StageStatus, TraceResponse, TraceStage, STAGE_ORDER } from "./types";
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
  summary: { total: 5, risk: 1, warning: 3, info: 1, possible: 1 },
  findings: [
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

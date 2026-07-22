import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_DEMO_TARGET,
  DEMO_GROUPS,
  DEMO_HYGIENE_REPORT,
  DEMO_RULES_UPDATED_AT,
  DEMO_TARGETS,
  DEMO_USERS,
  runDemoTrace,
  type DemoTarget,
} from "../demoData";
import { STAGE_ORDER } from "../types";
import type { MessageKey } from "@/i18n/en";
import type { NgfwUser, TraceResponse } from "../types";

/**
 * lib/demoData.ts — offline demo engine (iteration 5, FR-11). runDemoTrace is a
 * pure, synchronous function of (target, user, t): no fetch, no /api. The
 * OUTCOME is decided by the selected TARGET (not the user's group).
 */

// Minimal localizer: echoes the key so any category wiring is cheap to assert.
const t = ((key: MessageKey) => key) as (key: MessageKey) => string;

const SUCCESS = DEMO_TARGETS.find((x) => x.address === "success.com:443")!;
const FAILURE = DEMO_TARGETS.find((x) => x.address === "failure.com:8080")!;

function userByGroup(groupId: string): NgfwUser {
  const u = DEMO_USERS.find((x) => x.group_id === groupId);
  if (!u) throw new Error(`no demo user in group ${groupId}`);
  return u;
}

function stage(result: TraceResponse, key: string) {
  const s = result.stages.find((x) => x.key === key);
  if (!s) throw new Error(`stage ${key} missing`);
  return s;
}

describe("lib/demoData.ts — target fixtures (iteration 5)", () => {
  it("exposes exactly the two documented targets with expected outcomes", () => {
    expect(DEMO_TARGETS).toHaveLength(2);
    expect(SUCCESS.outcome).toBe("allowed");
    expect(SUCCESS.dst_port).toBe(443);
    expect(FAILURE.outcome).toBe("blocked");
    expect(FAILURE.dst_port).toBe(8080);
  });

  it("defaults the selected target to success.com:443", () => {
    expect(DEFAULT_DEMO_TARGET.address).toBe("success.com:443");
    expect(DEFAULT_DEMO_TARGET.outcome).toBe("allowed");
  });
});

describe("lib/demoData.ts — success.com:443 → allowed", () => {
  const subjects: Array<[string, NgfwUser | null]> = [
    ["admin user", userByGroup("g-admins")],
    ["guest user", userByGroup("g-guests")],
    ["no user", null],
  ];

  it.each(subjects)("%s → allowed, no block stage, destination pass", (_label, user) => {
    const result = runDemoTrace(SUCCESS, user, t);

    expect(result.summary.verdict).toBe("allowed");
    expect(result.summary.blocked_at).toBeNull();
    expect(result.summary.reached_destination).toBe(true);

    expect(result.stages.some((s) => s.status === "block")).toBe(false);
    expect(result.stages.some((s) => s.status === "na")).toBe(false);
    expect(stage(result, "destination").status).toBe("pass");
  });
});

describe("lib/demoData.ts — failure.com:8080 → blocked at firewall", () => {
  it("blocks on the firewall with a drop verdict", () => {
    const result = runDemoTrace(FAILURE, userByGroup("g-buh"), t);

    // Content filter passes before the firewall block.
    expect(stage(result, "content_filter").status).toBe("pass");

    const fw = stage(result, "firewall");
    expect(fw.status).toBe("block");
    expect(fw.detail?.action).toBe("drop");
    expect(fw.detail?.rule_name).toBe("Default deny (non-standard ports)");

    expect(result.summary.verdict).toBe("blocked");
    expect(result.summary.blocked_at).toBe("firewall");
    expect(result.summary.reached_destination).toBe(false);
  });

  it("marks stages after the firewall as na/blocked_upstream", () => {
    const result = runDemoTrace(FAILURE, userByGroup("g-buh"), t);
    const blockIndex = STAGE_ORDER.indexOf("firewall");

    result.stages.forEach((s, i) => {
      if (i > blockIndex) {
        expect(s.status).toBe("na");
        expect(s.detail?.reason_key).toBe("blocked_upstream");
      }
    });
    // Sanity: downstream stages exist (app_control/ips/destination).
    expect(result.stages.slice(blockIndex + 1).length).toBeGreaterThan(0);
  });
});

describe("lib/demoData.ts — outcome depends on target, not user group", () => {
  const groups = ["g-admins", "g-buh", "g-sales", "g-guests"];

  it.each(groups)("success.com is allowed for %s", (groupId) => {
    expect(runDemoTrace(SUCCESS, userByGroup(groupId), t).summary.verdict).toBe("allowed");
  });

  it.each(groups)("failure.com is blocked for %s", (groupId) => {
    expect(runDemoTrace(FAILURE, userByGroup(groupId), t).summary.verdict).toBe("blocked");
  });

  it("same target → same verdict regardless of user (incl. null)", () => {
    const blockedVerdicts = new Set([null, ...DEMO_USERS].map((u) => runDemoTrace(FAILURE, u, t).summary.verdict));
    expect([...blockedVerdicts]).toEqual(["blocked"]);

    const allowedVerdicts = new Set([null, ...DEMO_USERS].map((u) => runDemoTrace(SUCCESS, u, t).summary.verdict));
    expect([...allowedVerdicts]).toEqual(["allowed"]);
  });
});

describe("lib/demoData.ts — pipeline invariants", () => {
  const cases: Array<[string, DemoTarget, NgfwUser | null]> = [
    ["success/admin", SUCCESS, userByGroup("g-admins")],
    ["success/none", SUCCESS, null],
    ["failure/buh", FAILURE, userByGroup("g-buh")],
    ["failure/none", FAILURE, null],
  ];

  it.each(cases)("%s: always returns every stage in the fixed order", (_label, target, user) => {
    const result = runDemoTrace(target, user, t);

    expect(result.stages).toHaveLength(STAGE_ORDER.length);
    expect(result.stages.map((s) => s.key)).toEqual([...STAGE_ORDER]);
    expect(result.stages.map((s) => s.order)).toEqual(STAGE_ORDER.map((_k, i) => i + 1));
    for (const s of result.stages) {
      expect(s.title_key).toBe(`stage.${s.key}`);
      expect(["pass", "block", "skip", "bypass", "unknown", "na"]).toContain(s.status);
    }
  });

  it.each(cases)("%s: target is threaded into the result", (_label, target, user) => {
    const result = runDemoTrace(target, user, t);

    expect(result.target.input).toBe(target.address);
    expect(result.target.host).toBe(target.host);
    expect(result.target.dst_port).toBe(target.dst_port);
    expect(result.target.protocol).toBe("tcp");
    expect(result.target.resolved_ip).toBe(target.resolved_ip);
  });

  it.each(cases)("%s: result matches the contract TraceResponse shape", (_label, target, user) => {
    const result = runDemoTrace(target, user, t);

    // user shape (subset of NgfwUser: id/name/login) or null
    if (user) {
      expect(result.user).toEqual({ id: user.id, name: user.name, login: user.login });
    } else {
      expect(result.user).toBeNull();
    }

    expect(Array.isArray(result.categories)).toBe(true);
    expect(["allowed", "blocked", "conditional", "partial", "unknown"]).toContain(result.summary.verdict);
    expect(typeof result.summary.reached_destination).toBe("boolean");
    expect(result.summary.blocked_at === null || typeof result.summary.blocked_at === "string").toBe(true);
    expect(result.rules_updated_at).toBe(DEMO_RULES_UPDATED_AT);
  });

  it("port 443 vs 8080 is reflected in the target", () => {
    expect(runDemoTrace(SUCCESS, null, t).target.dst_port).toBe(443);
    expect(runDemoTrace(FAILURE, null, t).target.dst_port).toBe(8080);
  });
});

describe("lib/demoData.ts — offline guarantee (FR-11.1)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("does not call fetch and returns synchronously", () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const result = runDemoTrace(FAILURE, userByGroup("g-guests"), t);

    expect(result).not.toBeInstanceOf(Promise);
    expect(result.summary.verdict).toBe("blocked");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("lib/demoData.ts — demo fixtures", () => {
  it("exposes 5 demo groups", () => {
    const ids = DEMO_GROUPS.map((g) => g.id);
    expect(ids).toEqual(expect.arrayContaining(["g-admins", "g-it", "g-buh", "g-sales", "g-guests"]));
    expect(DEMO_GROUPS).toHaveLength(5);
  });

  it("every demo user references a known demo group", () => {
    const groupIds = new Set(DEMO_GROUPS.map((g) => g.id));
    for (const u of DEMO_USERS) {
      expect(u.group_id).not.toBeNull();
      expect(groupIds.has(u.group_id as string)).toBe(true);
    }
  });
});

describe("lib/demoData.ts — offline rule-hygiene report", () => {
  it("summary counts match the findings", () => {
    const f = DEMO_HYGIENE_REPORT.findings;
    expect(DEMO_HYGIENE_REPORT.summary.total).toBe(f.length);
    expect(DEMO_HYGIENE_REPORT.summary.risk).toBe(f.filter((x) => x.severity === "risk").length);
    expect(DEMO_HYGIENE_REPORT.summary.warning).toBe(f.filter((x) => x.severity === "warning").length);
    expect(DEMO_HYGIENE_REPORT.summary.info).toBe(f.filter((x) => x.severity === "info").length);
    expect(DEMO_HYGIENE_REPORT.summary.possible).toBe(f.filter((x) => x.tier === "possible").length);
  });

  it("showcases every finding kind and both tiers", () => {
    const kinds = new Set(DEMO_HYGIENE_REPORT.findings.map((f) => f.kind));
    expect(kinds).toEqual(new Set(["shadowed", "redundant", "unreachable_after_any", "overly_broad"]));
    const tiers = new Set(DEMO_HYGIENE_REPORT.findings.map((f) => f.tier));
    expect(tiers).toEqual(new Set(["certain", "possible"]));
  });

  it("mirrors the analyser semantics: a grouped catch-all lists its dead rules", () => {
    const grouped = DEMO_HYGIENE_REPORT.findings.find((f) => f.kind === "unreachable_after_any")!;
    expect(grouped.extra?.unreachable_count).toBe(grouped.related.length);
    // Shadow/redundant findings reference their earlier coverer.
    for (const f of DEMO_HYGIENE_REPORT.findings.filter((x) => x.kind === "shadowed" || x.kind === "redundant")) {
      expect(f.related).toHaveLength(1);
      expect(f.related[0]!.position).toBeLessThan(f.rule.position);
    }
  });
});
